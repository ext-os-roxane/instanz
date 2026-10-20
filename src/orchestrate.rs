//! `instanz` orchestration glue (PLAN 2.5.1 – 2.5.5).
//!
//! Everything in this module is a *consumer* of the `libextos` public API — no
//! pipeline logic is re-implemented here. The module owns exactly the pieces
//! that are CLI concerns:
//!
//! * mapping a [`SystemConfig`] to CAS refs and a dry [`VfsPlan`] (evaluate);
//! * the transactional order of an apply: fetch → snapshot → weave → phantom →
//!   post-weave tools → lockfile → generation record → `current` switch;
//! * generation listing, rollback and two-stage garbage collection.
//!
//! The pipeline is synchronous on purpose: `libextos::ingest` uses
//! `reqwest::blocking`, and running it inside a Tokio runtime panics with
//! "Cannot drop a runtime in a context where blocking is not allowed".
//!
//! All roots are caller-supplied ([`ApplyOptions::rootfs`], `--repository`);
//! nothing here hardcodes a production layout. The two documented production
//! mappings live at the CLI edge: `/repository` and
//! `/config/systems/default.nix`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, anyhow, bail};
use libextos::cas::{hash_bytes, CasRepository, LockEntry};
use libextos::config;
use libextos::ingest;
use libextos::manifest::PackageManifest;
use libextos::rosetta::registry::RosettaRegistry;
use libextos::snapshot::generation::{self, BlsEntry, GenerationTracker};
use libextos::snapshot::SnapshotEngine;
use libextos::types::HashAlgorithm;
use libextos::weaver::{
    self, CasRef, DagNode, DepGraph, LinkStrategy, OriginPriority, VfsPlan,
};

use crate::system::SystemConfig;

/// Parse the `--hash-algo` spelling used by `pkt` into a [`HashAlgorithm`].
pub fn parse_hash_algo(value: &str) -> HashAlgorithm {
    match value {
        "sha256" | "SHA256" => HashAlgorithm::Sha256,
        _ => HashAlgorithm::Blake3,
    }
}

/// Open (and if needed create) the CAS repository at `root`.
pub fn open_repo(root: &Path, algo: HashAlgorithm) -> anyhow::Result<CasRepository> {
    CasRepository::open(root, algo)
        .with_context(|| format!("cannot open CAS repository at {}", root.display()))
}

/// Abbreviate a CAS hash for terminal display without panicking on short input.
fn short_hash(hash: &str) -> &str {
    let end = hash.len().min(16);
    &hash[..end]
}

// ─── Evaluation ─────────────────────────────────────────────────

/// One resolved DAG node: the ref, its concrete hash and its edge count.
#[derive(Debug, Clone)]
pub struct ResolvedRef {
    /// The declared ref (version may be `current`).
    pub reference: CasRef,
    /// Version recorded in the manifest (or the ref's version).
    pub version: String,
    /// Concrete CAS object hash the ref resolves to.
    pub hash: String,
    /// Number of dependency edges this node contributes.
    pub deps: usize,
}

impl ResolvedRef {
    /// `origin/name` — the label the weaver uses as a provider.
    pub fn label(&self) -> String {
        format!("{}/{}", self.reference.origin, self.reference.name)
    }
}

/// A dry evaluation: the resolved DAG plus the plan it would execute.
pub struct Evaluation {
    /// The system config that was evaluated.
    pub system: SystemConfig,
    /// Resolved packages, in declaration order.
    pub resolved: Vec<ResolvedRef>,
    /// Total dependency edges between the resolved packages.
    pub edges: usize,
    /// The plan `apply` would execute.
    pub plan: VfsPlan,
    /// The roof-native PM the plan was evaluated for.
    pub native_pm: Option<String>,
}

impl Evaluation {
    /// Generation count of the DAG.
    pub fn node_count(&self) -> usize {
        self.resolved.len()
    }
}

/// Resolve the refs of `system` and build the (unexecuted) weave plan.
///
/// This never touches a rootfs: it only reads refs/manifests and computes the
/// plan, which is what makes `instanz evaluate` a safe dry run.
pub fn evaluate(repo: &CasRepository, system: SystemConfig) -> anyhow::Result<Evaluation> {
    if system.packages.is_empty() {
        bail!(
            "{}: `packages` is empty — nothing to evaluate",
            system.path.display()
        );
    }

    let native_pm = system
        .roof_native_pm
        .clone()
        .or_else(|| majority_origin(&system.packages));

    let mut resolved = Vec::with_capacity(system.packages.len());
    let mut graph = DepGraph::new();
    for reference in &system.packages {
        let hash = repo
            .resolve_ref(&reference.origin, &reference.name, &reference.version)
            .with_context(|| {
                format!(
                    "cannot resolve {} in {} (is it ingested? `pkt -S {}={}`)",
                    reference.label(),
                    repo.root.display(),
                    format_args!("{}/{}", reference.origin, reference.name),
                    reference.version
                )
            })?;
        let manifest = load_manifest(repo, &hash)
            .with_context(|| format!("manifest of {} is unreadable", reference.label()))?;
        let version = if manifest.identity.version.is_empty() {
            reference.version.clone()
        } else {
            manifest.identity.version.clone()
        };

        graph.insert(DagNode {
            hash: hash.clone(),
            identity: libextos::manifest::PackageIdentity {
                origin: reference.origin.clone(),
                name: reference.name.clone(),
                version: version.clone(),
                aliases: manifest.identity.aliases.clone(),
            },
            capabilities: manifest.capabilities.clone(),
            deps: Vec::new(),
            requires: manifest.requires.clone(),
        });
        resolved.push(ResolvedRef {
            reference: reference.clone(),
            version,
            hash,
            deps: 0,
        });
    }

    graph.link_requires();
    let mut edges = 0;
    for (index, row) in resolved.iter_mut().enumerate() {
        row.deps = graph.nodes.get(index).map(|n| n.deps.len()).unwrap_or(0);
        edges += row.deps;
    }

    let plan = weaver::plan_from_refs_with(
        repo,
        &system.packages,
        LinkStrategy::Reflink,
        &OriginPriority::new(),
    )
    .with_context(|| format!("cannot plan {}", system.path.display()))?;

    Ok(Evaluation {
        system,
        resolved,
        edges,
        plan,
        native_pm,
    })
}

/// Load and parse the manifest stored for `hash`.
fn load_manifest(repo: &CasRepository, hash: &str) -> anyhow::Result<PackageManifest> {
    let text = repo.read_manifest(hash)?;
    let value = config::parse_nix(&text)
        .with_context(|| format!("cannot parse manifest.nix of object {}", short_hash(hash)))?;
    PackageManifest::from_nix(&value)
        .with_context(|| format!("invalid manifest for object {}", short_hash(hash)))
}

/// Origin providing the most packages (ties broken alphabetically).
fn majority_origin(refs: &[CasRef]) -> Option<String> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for r in refs {
        *counts.entry(r.origin.as_str()).or_default() += 1;
    }
    counts
        .into_iter()
        .fold(None::<(&str, usize)>, |best, (origin, count)| match best {
            Some((_, best_count)) if best_count >= count => best,
            _ => Some((origin, count)),
        })
        .map(|(origin, _)| origin.to_string())
}

/// Print the human-readable DAG/plan summary of an evaluation.
pub fn print_evaluation(eval: &Evaluation, repo: &CasRepository) {
    println!("System        : {}", eval.system.name);
    println!("Config        : {}", eval.system.path.display());
    println!("Repository    : {}", repo.root.display());
    match &eval.native_pm {
        Some(pm) => println!("Roof native PM: {pm}"),
        None => println!("Roof native PM: none"),
    }
    if let Some(kernel) = &eval.system.kernel {
        println!("Kernel        : {kernel}");
    }
    if !eval.system.services.is_empty() {
        println!("Services      : {}", eval.system.services.join(", "));
    }
    println!();
    println!(
        "DAG ({} node(s), {} edge(s)):",
        eval.node_count(),
        eval.edges
    );
    for row in &eval.resolved {
        println!(
            "  {}/{} {} → {} ({} dep(s))",
            row.reference.origin,
            row.reference.name,
            row.version,
            short_hash(&row.hash),
            row.deps
        );
    }

    let plan = &eval.plan;
    println!();
    println!(
        "Plan: {} op(s) [dirs {}, files {}, symlinks {}, wrappers {}]; \
         collisions {}, warnings {}",
        plan.len(),
        plan.directory_ops(),
        plan.file_ops(),
        plan.symlink_ops(),
        plan.wrapper_ops(),
        plan.collisions().len(),
        plan.warnings().len()
    );
    for warning in plan.warnings() {
        println!("  note: {warning}");
    }
}

// ─── Apply ──────────────────────────────────────────────────────

/// Output locations for one `instanz apply`.
pub struct ApplyOptions<'a> {
    /// Generations root: holds `gen-<n>/`, `current` and `generations.json`.
    pub rootfs: &'a Path,
    /// Repository download cache (stale `.part` files are swept on failure).
    pub cache_dir: &'a Path,
    /// BLS entries directory; `None` keeps apply symlink-only.
    pub bls_dir: Option<&'a Path>,
}

/// What one successful apply produced.
#[derive(Debug, Clone)]
pub struct ApplyReport {
    /// Generation number that is now current.
    pub generation: u64,
    /// Woven tree of that generation.
    pub root: PathBuf,
    /// Number of plan operations applied.
    pub plan_ops: usize,
    /// Phantom rows (canonical + spoofed) written.
    pub phantom_rows: usize,
    /// Lockfile written into the generation.
    pub lockfile: PathBuf,
}

/// Execute the full local pipeline for `system`.
///
/// Order (a failure never deletes the snapshot created before the weave):
/// 1. evaluate; 2. fetch+ingest missing refs; 3. snapshot/prime `gen-<n>`;
/// 4. plan; 5. execute; 6. phantom rows; 7. `ldconfig`/`depmod`;
/// 8. lockfile + generation record + `current` switch.
pub fn apply(repo: &CasRepository, system: SystemConfig, opts: &ApplyOptions<'_>) -> anyhow::Result<ApplyReport> {
    match apply_inner(repo, system, opts) {
        Ok(report) => Ok(report),
        Err(err) => {
            let swept = sweep_part_files(opts.cache_dir);
            if swept > 0 {
                eprintln!("cleanup: removed {swept} stale `.part` download(s)");
            }
            Err(err)
        }
    }
}

fn apply_inner(
    repo: &CasRepository,
    system: SystemConfig,
    opts: &ApplyOptions<'_>,
) -> anyhow::Result<ApplyReport> {
    const STEPS: usize = 8;

    println!("[1/{STEPS}] evaluate {}", system.path.display());
    let missing = probe_missing(repo, &system.packages);
    println!(
        "        {} declared ref(s), {} present, {} missing",
        system.packages.len(),
        system.packages.len() - missing.len(),
        missing.len()
    );
    for reference in &missing {
        println!("        · {} is not in the CAS yet", reference.label());
    }

    println!("[2/{STEPS}] fetch missing packages");
    let fetched = fetch_missing(repo, &system.packages, opts.cache_dir)?;
    println!(
        "        {} fetched, {} already in the CAS",
        fetched,
        system.packages.len() - fetched
    );

    // Full evaluation needs every manifest, so it runs after the fetch step.
    println!("[3/{STEPS}] plan (reflink, origin priority)");
    let eval = evaluate(repo, system)?;
    let plan = &eval.plan;
    println!(
        "        {} node(s), {} edge(s), {} op(s) [dirs {}, files {}, symlinks {}, wrappers {}], collisions {}",
        eval.node_count(),
        eval.edges,
        plan.len(),
        plan.directory_ops(),
        plan.file_ops(),
        plan.symlink_ops(),
        plan.wrapper_ops(),
        plan.collisions().len()
    );

    println!("[4/{STEPS}] snapshot before weave");
    let engine = SnapshotEngine::open(opts.rootfs)
        .with_context(|| format!("cannot open generations root {}", opts.rootfs.display()))?;
    let mut tracker = GenerationTracker::open(opts.rootfs)
        .with_context(|| format!("cannot read generation tracker in {}", opts.rootfs.display()))?;
    let number = next_generation_number(&engine, &tracker)?;
    let snapshot = match engine.current_generation()? {
        Some(current) => engine
            .create_snapshot(&engine.gen_path(current), number)
            .with_context(|| format!("cannot snapshot gen-{current} → gen-{number}"))?,
        None => engine
            .create_empty(number)
            .with_context(|| format!("cannot create gen-{number}"))?,
    };
    println!(
        "        gen-{number} ← {} ({:?})",
        snapshot.path.display(),
        snapshot.backend
    );

    println!("[5/{STEPS}] weave → {}", snapshot.path.display());
    let execution = weaver::execute_plan(plan, &snapshot.path).context("weave failed")?;
    println!(
        "        {} dir(s), {} file(s), {} symlink(s), {} wrapper(s), {} reused, {} fallback(s)",
        execution.directories_created,
        execution.files_linked,
        execution.symlinks_created,
        execution.wrappers_written,
        execution.reused,
        execution.fallbacks
    );

    println!("[6/{STEPS}] phantom rows");
    let phantom_rows = write_phantoms(repo, &eval, &snapshot.path)
        .context("phantom database generation failed")?;
    println!("        {phantom_rows} row(s) written");

    println!("[7/{STEPS}] post-weave tools");
    postprocess(&snapshot.path, eval.system.kernel.as_deref())?;
    println!("        initramfs: deferred to Phase 4 (runlevel 0 forges, PLAN 4.2)");

    println!("[8/{STEPS}] lockfile + generation record");
    let lockfile = snapshot.path.join(".lock");
    let entries = resolve_locks(repo, &eval.system.packages)?;
    repo.write_lockfile(&entries, &lockfile)
        .with_context(|| format!("cannot write {}", lockfile.display()))?;
    let lock_bytes = fs::read(&lockfile)?;
    let lock_hash = hash_bytes(&lock_bytes, repo.algo);
    tracker.record(
        number,
        Some(lock_hash),
        &format!("instanz apply: {} package(s)", entries.len()),
    )?;

    if let Some(entries_dir) = opts.bls_dir {
        write_bls_entry(entries_dir, &eval.system, number)?;
        println!("        BLS entry {}/gen-{number}.conf", entries_dir.display());
    } else {
        println!("        BLS entry skipped: EXTOS_BLS_DIR is not set (symlink-only mode)");
    }

    engine
        .switch_to(number)
        .with_context(|| format!("cannot switch `current` to gen-{number}"))?;
    println!("        ✓ generation {number} is now current");
    println!(
        "✓ applied {} → {} ({} op(s), {} phantom row(s))",
        eval.system.name,
        snapshot.path.display(),
        execution.journal.len(),
        phantom_rows
    );

    Ok(ApplyReport {
        generation: number,
        root: snapshot.path,
        plan_ops: execution.journal.len(),
        phantom_rows,
        lockfile,
    })
}

/// Highest of "tracker says next" and "newest generation on disk + 1".
fn next_generation_number(engine: &SnapshotEngine, tracker: &GenerationTracker) -> anyhow::Result<u64> {
    let from_tracker = tracker.next_number();
    let from_disk = engine
        .list()?
        .iter()
        .map(|g| g.generation)
        .max()
        .map(|n| n + 1)
        .unwrap_or(1);
    Ok(from_tracker.max(from_disk))
}

/// Declared refs that do not resolve in the CAS yet (candidates for a fetch).
fn probe_missing(repo: &CasRepository, refs: &[CasRef]) -> Vec<CasRef> {
    refs.iter()
        .filter(|r| repo.resolve_ref(&r.origin, &r.name, &r.version).is_err())
        .cloned()
        .collect()
}

/// Download + ingest every ref that is not yet in the CAS.
///
/// Refs already present are left untouched (no network). A missing ref with no
/// configured mirror fails with the same hint `pkt -S` prints, never a panic.
fn fetch_missing(repo: &CasRepository, refs: &[CasRef], cache_dir: &Path) -> anyhow::Result<usize> {
    let rosetta = RosettaRegistry::default();
    let mut fetched = 0;

    for reference in refs {
        if repo
            .resolve_ref(&reference.origin, &reference.name, &reference.version)
            .is_ok()
        {
            println!("        · {} (cached)", reference.label());
            continue;
        }

        let archive =
            ingest::download_from_mirror_to(&reference.origin, &reference.name, &reference.version, cache_dir)
                .map_err(|err| {
                    anyhow!(
                        "cannot fetch {}: {err}\n\
                         hint: set {} to one or more comma-separated mirror base URLs",
                        reference.label(),
                        ingest::mirror_env_var(&reference.origin)
                    )
                })?;
        println!("        ↓ {} ({})", archive.display(), reference.label());

        let result = ingest::ingest_local_archive_with_rosetta(
            repo,
            &archive,
            &reference.origin,
            Some(&rosetta),
        )
        .with_context(|| format!("cannot ingest {} as {}", archive.display(), reference.origin))?;
        repo.resolve_ref(&reference.origin, &reference.name, &reference.version)
            .map_err(|err| {
                anyhow!(
                    "ingested {}/{} {} from {}, but the ref is missing: {err}",
                    result.origin,
                    result.name,
                    result.version,
                    archive.display()
                )
            })?;
        fetched += 1;
        println!(
            "        ✓ {}/{} {} → {}",
            result.origin,
            result.name,
            result.version,
            short_hash(&result.hash)
        );
    }

    Ok(fetched)
}

/// Write canonical (and spoofed) phantom rows for every woven package.
fn write_phantoms(repo: &CasRepository, eval: &Evaluation, root: &Path) -> anyhow::Result<usize> {
    // Files are attributed to the package that contributed the plan op; the VFS
    // is the single source of truth for ownership, so no re-scan is needed.
    let mut files_by_provider: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in eval.plan.entries() {
        if entry.provider == "extos/weaver" {
            continue;
        }
        files_by_provider
            .entry(entry.provider.clone())
            .or_default()
            .push(entry.rel_path().to_string_lossy().into_owned());
    }

    let mut rows = 0;
    for row in &eval.resolved {
        let label = row.label();
        let files = files_by_provider.remove(&label).unwrap_or_default();
        let manifest = load_manifest(repo, &row.hash)
            .with_context(|| format!("manifest of {label} is unreadable"))?;
        let written = libextos::phantom::write_all_phantoms(
            &manifest,
            root,
            &files,
            eval.native_pm.as_deref(),
        )
        .with_context(|| format!("cannot write phantom rows for {label}"))?;
        if !written.is_empty() {
            println!("        {label}: {}", written.join(", "));
        }
        rows += written.len();
    }
    Ok(rows)
}

/// Resolve every declared ref to a concrete [`LockEntry`] (`current` included).
fn resolve_locks(repo: &CasRepository, refs: &[CasRef]) -> anyhow::Result<Vec<LockEntry>> {
    refs.iter()
        .map(|r| {
            repo.resolve_lock(&r.origin, &r.name, &r.version)
                .with_context(|| format!("cannot lock {}", r.label()))
        })
        .collect()
}

/// Write the BLS entry for `number` (needs `linux = "…"` in the config).
fn write_bls_entry(entries_dir: &Path, system: &SystemConfig, number: u64) -> anyhow::Result<()> {
    let linux = system.linux.as_ref().ok_or_else(|| {
        anyhow!(
            "EXTOS_BLS_DIR is set but {} declares no `linux = \"…\";` boot image path",
            system.path.display()
        )
    })?;
    let entry = BlsEntry {
        title: format!("ExtOS {}", system.name),
        version: system
            .kernel
            .clone()
            .unwrap_or_else(|| number.to_string()),
        machine_id: None,
        sort_key: Some(system.name.clone()),
        linux: linux.clone(),
        initrd: Vec::new(),
        options: None,
    };
    entry
        .write(entries_dir, number)
        .with_context(|| format!("cannot write BLS entry to {}", entries_dir.display()))?;
    Ok(())
}

/// Run the strict post-weave tools, announcing every skip explicitly.
fn postprocess(root: &Path, kernel: Option<&str>) -> anyhow::Result<()> {
    match weaver::run_ldconfig(root) {
        Ok(outcome) => println!(
            "        ✓ {} {}",
            outcome.program,
            outcome.arguments.join(" ")
        ),
        Err(err) => {
            let message = err.to_string();
            if message.contains("not found") {
                println!("        ⚠ ldconfig skipped: {message}");
            } else {
                return Err(anyhow::Error::new(err).context("post-weave ldconfig failed"));
            }
        }
    }

    match kernel {
        Some(version) => match weaver::run_depmod(root, version) {
            Ok(outcome) => println!(
                "        ✓ {} {}",
                outcome.program,
                outcome.arguments.join(" ")
            ),
            Err(err) => {
                let message = err.to_string();
                if message.contains("not found") {
                    println!("        ⚠ depmod skipped: {message}");
                } else {
                    return Err(anyhow::Error::new(err).context("post-weave depmod failed"));
                }
            }
        },
        None => println!(
            "        ⚠ depmod skipped: the system config declares no `kernel = \"…\";` version"
        ),
    }

    Ok(())
}

/// Remove stale `*.part` download files left behind by an interrupted fetch.
///
/// Only the repository cache is swept — an apply failure must never delete the
/// snapshot it already created (rollback relies on it).
fn sweep_part_files(cache_dir: &Path) -> usize {
    fn walk(dir: &Path, removed: &mut usize) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.is_dir() {
                walk(&path, removed);
            } else if path.extension().and_then(|e| e.to_str()) == Some("part")
                && fs::remove_file(&path).is_ok()
            {
                *removed += 1;
            }
        }
    }

    let mut removed = 0;
    walk(cache_dir, &mut removed);
    removed
}

// ─── Rollback ───────────────────────────────────────────────────

/// Which generation a rollback should activate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackTarget {
    /// The newest generation older than the current one.
    Previous,
    /// An explicit generation number.
    Number(u64),
}

impl RollbackTarget {
    /// Parse `--generation` (`prev`, `previous`, `` or a number).
    pub fn parse(value: Option<&str>) -> anyhow::Result<Self> {
        match value.map(str::trim) {
            None | Some("") | Some("prev") | Some("previous") => Ok(Self::Previous),
            Some(text) => text
                .parse::<u64>()
                .map(Self::Number)
                .map_err(|_| anyhow!("invalid generation `{text}`: expected `prev` or a number")),
        }
    }
}

/// Switch `current` (and the BLS default, when configured) to an older generation.
pub fn rollback(
    rootfs: &Path,
    target: RollbackTarget,
    bls_dir: Option<&Path>,
) -> anyhow::Result<u64> {
    let engine = SnapshotEngine::open(rootfs)
        .with_context(|| format!("cannot open generations root {}", rootfs.display()))?;
    let generations = engine.list()?;
    if generations.is_empty() {
        bail!("no generations under {}", rootfs.display());
    }
    let current = engine.current_generation()?;
    let target_number = match target {
        RollbackTarget::Number(number) => number,
        RollbackTarget::Previous => generations
            .iter()
            .map(|g| g.generation)
            .filter(|n| current.is_none_or(|c| *n < c))
            .max()
            .ok_or_else(|| {
                anyhow!(
                    "no previous generation under {} (current: {})",
                    rootfs.display(),
                    current.map(|c| c.to_string()).unwrap_or_else(|| "none".into())
                )
            })?,
    };

    let tracker = GenerationTracker::open(rootfs)?;
    let title = tracker
        .get(target_number)
        .map(|g| g.description.clone())
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| format!("generation {target_number}"));
    let from = current
        .map(|c| c.to_string())
        .unwrap_or_else(|| "none".to_string());

    if current == Some(target_number) {
        println!("rollback: generation {target_number} is already current ({title})");
        return Ok(target_number);
    }

    engine
        .switch_to(target_number)
        .with_context(|| format!("cannot switch `current` to gen-{target_number}"))?;
    println!("rollback: generation {from} → {target_number} ({title})");

    match bls_dir {
        Some(dir) => {
            let conf = set_bls_default(dir, target_number)?;
            println!("  BLS default {} → {}", conf.display(), BlsEntry::file_name(target_number));
        }
        None => println!("  BLS default skipped: EXTOS_BLS_DIR is not set (symlink-only mode)"),
    }

    Ok(target_number)
}

/// Point the boot loader's default at `gen-<n>.conf`.
///
/// `loader.conf` sits next to `entries/` in a BLS layout
/// (`/boot/loader/loader.conf`, `/boot/loader/entries/gen-<n>.conf`), so the
/// file is derived from the entries directory. The `default` line is replaced;
/// every other line is preserved verbatim.
fn set_bls_default(entries_dir: &Path, generation: u64) -> anyhow::Result<PathBuf> {
    let loader_dir = entries_dir
        .parent()
        .ok_or_else(|| anyhow!("EXTOS_BLS_DIR {} has no parent directory", entries_dir.display()))?;
    let conf = loader_dir.join("loader.conf");
    let existing = match fs::read_to_string(&conf) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(anyhow::Error::new(err).context(format!("cannot read {}", conf.display()))),
    };

    let mut lines: Vec<&str> = existing
        .lines()
        .filter(|line| !line.trim_start().starts_with("default "))
        .collect();
    let wanted = format!("default {}", BlsEntry::file_name(generation));
    lines.push(&wanted);

    let mut content = lines.join("\n");
    content.push('\n');
    fs::create_dir_all(loader_dir)?;
    fs::write(&conf, content)
        .with_context(|| format!("cannot write {}", conf.display()))?;
    Ok(conf)
}

// ─── Garbage collection ─────────────────────────────────────────

/// Result of the two GC stages.
#[derive(Debug, Clone, Default)]
pub struct GcReport {
    /// Generation numbers purged from the system root.
    pub generations: Vec<u64>,
    /// CAS object hashes purged from the repository.
    pub objects: Vec<String>,
}

/// Purge old generations, then unreferenced CAS objects.
///
/// The stages are independent: both always run and both are reported. If the
/// generation stage fails its error is returned *after* the CAS stage, so the
/// operator sees one coherent report instead of a half-printed one.
pub fn gc(
    repo: &CasRepository,
    rootfs: &Path,
    keep: usize,
    bls_dir: Option<&Path>,
) -> anyhow::Result<GcReport> {
    println!("stage 1/2: generations (keep {keep})");
    let engine = SnapshotEngine::open(rootfs)
        .with_context(|| format!("cannot open generations root {}", rootfs.display()))?;
    let mut tracker = GenerationTracker::open(rootfs)?;
    let generation_result =
        generation::gc_with_entries(&engine, &mut tracker, keep, bls_dir);

    let mut report = GcReport::default();
    let mut generation_error = None;
    match generation_result {
        Ok(removed) => {
            println!(
                "  purged {} generation(s){}",
                removed.len(),
                if removed.is_empty() {
                    String::new()
                } else {
                    format!(": {}", removed.iter().map(|n| format!("gen-{n}")).collect::<Vec<_>>().join(", "))
                }
            );
            report.generations = removed;
        }
        Err(err) => {
            eprintln!("  error: {err}");
            generation_error = Some(anyhow::Error::new(err).context("generation GC failed"));
        }
    }

    println!("stage 2/2: CAS objects");
    let purged = repo
        .gc()
        .with_context(|| format!("CAS GC failed in {}", repo.root.display()))?;
    println!("  purged {} unreferenced object(s)", purged.len());
    report.objects = purged;

    match generation_error {
        Some(err) => Err(err),
        None => Ok(report),
    }
}

// ─── Generations ────────────────────────────────────────────────

/// One row of `instanz generations`.
#[derive(Debug, Clone)]
pub struct GenerationRow {
    /// Generation number.
    pub number: u64,
    /// Tracker timestamp (seconds since the epoch), if recorded.
    pub timestamp: Option<u64>,
    /// Packages recorded in the generation's `.lock` file.
    pub packages: Vec<String>,
    /// Tracker description, if any.
    pub description: String,
    /// Whether `current` points here.
    pub is_current: bool,
    /// Whether the generation is pinned against GC.
    pub pinned: bool,
}

/// List generations on disk, enriched with tracker metadata and lockfiles.
pub fn generations(rootfs: &Path) -> anyhow::Result<Vec<GenerationRow>> {
    let engine = SnapshotEngine::open(rootfs)
        .with_context(|| format!("cannot open generations root {}", rootfs.display()))?;
    let tracker = GenerationTracker::open(rootfs)?;
    let current = engine.current_generation()?;

    let mut rows: Vec<GenerationRow> = engine
        .list()?
        .into_iter()
        .map(|snapshot| {
            let record = tracker.get(snapshot.generation);
            GenerationRow {
                number: snapshot.generation,
                timestamp: record.map(|r| r.timestamp),
                packages: read_lock_packages(&snapshot.path.join(".lock")),
                description: record
                    .map(|r| r.description.clone())
                    .unwrap_or_default(),
                is_current: current == Some(snapshot.generation),
                pinned: record.map(|r| r.pinned).unwrap_or(false),
            }
        })
        .collect();
    rows.sort_by_key(|row| row.number);
    Ok(rows)
}

/// Read `"origin/name" = { … hash = "…"; };` keys from a lockfile.
fn read_lock_packages(lock: &Path) -> Vec<String> {
    let Ok(text) = fs::read_to_string(lock) else {
        return Vec::new();
    };
    text.lines()
        .filter(|line| line.contains("hash = "))
        .filter_map(|line| {
            let start = line.find('"')?;
            let rest = &line[start + 1..];
            let end = rest.find('"')?;
            Some(rest[..end].to_string())
        })
        .collect()
}

/// Print the generation table (`*` marks the current generation).
pub fn print_generations(rootfs: &Path, rows: &[GenerationRow]) {
    println!("Generations under {}", rootfs.display());
    if rows.is_empty() {
        println!("  (none)");
        return;
    }
    for row in rows {
        let marker = if row.is_current { '*' } else { ' ' };
        let time = row
            .timestamp
            .map(format_utc)
            .unwrap_or_else(|| "unknown time".to_string());
        let pinned = if row.pinned { "  [pinned]" } else { "" };
        let packages = if row.packages.is_empty() {
            "no lockfile".to_string()
        } else {
            format!("{} package(s): {}", row.packages.len(), row.packages.join(", "))
        };
        println!("{marker} gen-{}  {time}  {packages}{pinned}", row.number);
        if !row.description.is_empty() {
            println!("       {}", row.description);
        }
    }
}

/// Format seconds since the epoch as `YYYY-MM-DD HH:MM:SS UTC`.
fn format_utc(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let rem = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's `civil_from_days` (days since 1970-01-01 → y/m/d).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollback_target_parsing() {
        assert_eq!(RollbackTarget::parse(None).unwrap(), RollbackTarget::Previous);
        assert_eq!(RollbackTarget::parse(Some("prev")).unwrap(), RollbackTarget::Previous);
        assert_eq!(RollbackTarget::parse(Some("  ")).unwrap(), RollbackTarget::Previous);
        assert_eq!(RollbackTarget::parse(Some("7")).unwrap(), RollbackTarget::Number(7));
        assert!(RollbackTarget::parse(Some("latest")).is_err());
    }

    #[test]
    fn timestamp_formatting_matches_epoch_day() {
        assert_eq!(format_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_utc(1_700_000_000), "2023-11-14 22:13:20 UTC");
        assert_eq!(format_utc(1_767_225_600), "2026-01-01 00:00:00 UTC");
    }

    #[test]
    fn majority_origin_breaks_ties_alphabetically() {
        let refs = vec![
            CasRef::new("debian", "a", "1"),
            CasRef::new("archlinux", "b", "1"),
            CasRef::new("archlinux", "c", "1"),
        ];
        assert_eq!(majority_origin(&refs).as_deref(), Some("archlinux"));

        let tie = vec![CasRef::new("debian", "a", "1"), CasRef::new("alpine", "b", "1")];
        assert_eq!(majority_origin(&tie).as_deref(), Some("alpine"));
        assert_eq!(majority_origin(&[]), None);
    }

    #[test]
    fn sweep_only_removes_part_files() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("cache/archlinux");
        fs::create_dir_all(&cache).unwrap();
        fs::write(cache.join("a.part"), b"partial").unwrap();
        fs::write(cache.join("b.pkg.tar.zst"), b"whole").unwrap();

        assert_eq!(sweep_part_files(tmp.path().join("cache").as_path()), 1);
        assert!(!cache.join("a.part").exists());
        assert!(cache.join("b.pkg.tar.zst").exists());
    }

    #[test]
    fn bls_default_is_replaced_not_duplicated() {
        let tmp = tempfile::tempdir().unwrap();
        let entries = tmp.path().join("loader/entries");
        fs::create_dir_all(&entries).unwrap();
        let conf = tmp.path().join("loader/loader.conf");
        fs::write(&conf, "timeout 3\ndefault gen-1.conf\neditor no\n").unwrap();

        let written = set_bls_default(&entries, 2).unwrap();
        assert_eq!(written, conf);
        let text = fs::read_to_string(&conf).unwrap();
        assert_eq!(text, "timeout 3\neditor no\ndefault gen-2.conf\n");
    }

    #[test]
    fn lock_packages_are_parsed_from_lockfile_text() {
        let tmp = tempfile::tempdir().unwrap();
        let lock = tmp.path().join(".lock");
        fs::write(
            &lock,
            "# ExtOS Lockfile\n{\n  \"archlinux/htop\" = { version = \"3.3.0-1\"; hash = \"ab\"; };\n  \"debian/bash\" = { version = \"5.2\"; hash = \"cd\"; };\n}\n",
        )
        .unwrap();
        assert_eq!(
            read_lock_packages(&lock),
            vec!["archlinux/htop".to_string(), "debian/bash".to_string()]
        );
        assert!(read_lock_packages(&tmp.path().join("missing")).is_empty());
    }
}
