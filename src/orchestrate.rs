//! `instanz` orchestration glue (PLAN 2.5.1 – 2.5.5).
//!
//! Everything in this module is a *consumer* of the `libextos` public API — no
//! pipeline logic is re-implemented here. The module owns exactly the pieces
//! that are CLI concerns:
//!
//! * mapping a [`SystemConfig`] to CAS refs and a dry [`VfsPlan`] (evaluate);
//! * the transactional order of an apply: fetch → snapshot → weave → phantom →
//!   post-weave tools → **runlevel-0 forge** → lockfile → generation record →
//!   `current` switch → orphan sweep;
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
//!
//! # Runlevel-0 forge trigger (PLAN 4.2.6)
//!
//! Step 10 hands the woven system to [`crate::forge::run_forge`], which derives a
//! Forge blueprint from the config (the derivation table lives in that module's
//! docs) and adds two things `apply` never had in Phase 2: an initramfs built
//! inside the forge namespace, and the BLS entry matrix under the caller's boot
//! root (`--boot-root` / `EXTOS_BLS_ROOT`), including the `loader.conf`
//! `CreateIfMissing` policy. A forge that cannot run is recorded as
//! `forge=skipped` in the generation description and never fails the apply; a
//! forge that *fails* is fatal, because it means the blueprint or the generator
//! is wrong. `EXTOS_BLS_DIR` keeps its Phase-2 meaning (a raw entries directory
//! with `gen-<n>.conf` snapshot entries) and does not forge.
//!
//! Step 11 ends with [`crate::reaper::reap`], which removes `gen-<n>` orphans
//! left by aborted applies (never the current generation, never a recorded one,
//! never one a BLS entry points at, never the youngest on disk). `EXTOS_REAPER=off`
//! disables it; deletion failures are logged and non-fatal.
//!
//! # Service enable/disable (PLAN 7.2.2)
//!
//! Step 6 ends with a wants-dir reconcile ([`reconcile_services`]): every
//! name declared in the config's `services` list gets a *relative*
//! `etc/systemd/system/multi-user.target.wants/<name>.service` symlink into
//! the roof's `/usr/lib/systemd/system` — the FHS location the weaver places
//! packaged units at — provided the unit file exists in the roof's standard
//! unit search path. A declared service whose unit is absent anywhere in the
//! roof (its package is not woven) is an honest warning, never a failure.
//! Services that were enabled by an earlier apply but are no longer declared
//! are disabled; the bookkeeping marker
//! (`etc/systemd/.extos-enabled-services`) makes apply touch *only* symlinks
//! it created itself — operator- and tooling-owned wants entries are never
//! removed, clobbered, or recorded (see [`ENABLED_SERVICES_MARKER`]).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, anyhow, bail};
use libextos::anchor::AnchorPolicy;
use libextos::cas::{hash_bytes, CasRepository, LockEntry};
use libextos::forge::bls::{entries_dir as bls_entries_dir, set_loader_default};
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

use crate::forge::{self, ForgeReport, ForgeRequest, PackageSource};
use crate::mount::{
    apply_mounts, plan_mounts, probe_mount_capability, HostMountRunner, MountOutcome, MountSources,
};
use crate::reaper::{self, ReapReport};
use crate::system::{ExpandedPackages, SystemConfig};

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
    /// Groups/virtuals flattened into concrete refs (PLAN 4.1.2).
    pub expansion: ExpandedPackages,
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
    let expansion = system.expand(repo)?;
    evaluate_expanded(repo, system, expansion)
}

/// [`evaluate`] with an already-expanded package list (PLAN 4.1.2).
///
/// `apply` expands once so the fetch step and the plan agree on the exact ref
/// set; a second expansion could otherwise observe a CAS that changed mid-apply.
fn evaluate_expanded(
    repo: &CasRepository,
    system: SystemConfig,
    expansion: ExpandedPackages,
) -> anyhow::Result<Evaluation> {
    if expansion.refs.is_empty() {
        bail!(
            "{}: `packages` expands to nothing — nothing to evaluate",
            system.path.display()
        );
    }

    let native_pm = system
        .roof_native_pm
        .clone()
        .or_else(|| majority_origin(&expansion.refs));

    let mut resolved = Vec::with_capacity(expansion.refs.len());
    let mut graph = DepGraph::new();
    for reference in &expansion.refs {
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

    let plan = weaver::plan::plan_from_refs_with_anchors(
        repo,
        &expansion.refs,
        LinkStrategy::Reflink,
        &OriginPriority::new(),
        &AnchorPolicy::new(),
    )
    .with_context(|| format!("cannot plan {}", system.path.display()))?;

    Ok(Evaluation {
        system,
        expansion,
        resolved,
        edges,
        plan,
        native_pm,
    })
}

/// Load and parse the manifest stored for `hash`.
pub(crate) fn load_manifest(repo: &CasRepository, hash: &str) -> anyhow::Result<PackageManifest> {
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
    // Declared entries (groups/virtuals included) vs. the flattened ref set.
    println!(
        "Declared      : {} entr(ies) [{}] — {} directly declared ref(s)",
        eval.system.entries.len(),
        eval.system
            .entries
            .iter()
            .map(|entry| entry.label())
            .collect::<Vec<_>>()
            .join(", "),
        eval.system.packages.len()
    );
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
    if let Some(boot) = eval.system.boot.cmdline.as_deref() {
        println!("Boot cmdline  : {boot}");
    }
    if !eval.system.boot.modules.is_empty() {
        println!("Boot modules  : {}", eval.system.boot.modules.join(", "));
    }
    if !eval.expansion.groups.is_empty() {
        let groups = eval
            .expansion
            .groups
            .iter()
            .map(|(name, count)| format!("@{name} ({count})"))
            .collect::<Vec<_>>()
            .join(", ");
        println!("Groups        : {groups}");
    }
    if !eval.expansion.virtuals.is_empty() {
        let virtuals = eval
            .expansion
            .virtuals
            .iter()
            .map(|(name, reference)| format!("{name} → {}", reference.label()))
            .collect::<Vec<_>>()
            .join(", ");
        println!("Virtuals      : {virtuals}");
    }
    for note in &eval.expansion.notes {
        println!("  note: {note}");
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

    let anchors = plan.anchors();
    if !anchors.is_empty() {
        println!();
        println!("SONAME anchors ({}):", anchors.len());
        for choice in anchors.choices() {
            let losers = choice.losers();
            if losers.is_empty() {
                println!(
                    "  {} → {} (priority {}, sole provider)",
                    choice.soname, choice.winner, choice.priority
                );
            } else {
                println!(
                    "  {} → {} (priority {}, over {})",
                    choice.soname,
                    choice.winner,
                    choice.priority,
                    losers.join(", ")
                );
            }
        }
    }
}

// ─── Apply ──────────────────────────────────────────────────────

/// Output locations for one `instanz apply`.
pub struct ApplyOptions<'a> {
    /// Generations root: holds `gen-<n>/`, `current` and `generations.json`.
    pub rootfs: &'a Path,
    /// Repository download cache (stale `.part` files are swept on failure).
    pub cache_dir: &'a Path,
    /// Legacy BLS entries directory (`EXTOS_BLS_DIR`): snapshot-only
    /// `gen-<n>.conf` entries, no forge. `None` keeps apply symlink-only.
    pub bls_dir: Option<&'a Path>,
    /// Boot root for the runlevel-0 forge (`--boot-root` / `EXTOS_BLS_ROOT`):
    /// the initramfs artifact and the BLS matrix land here.
    pub boot_root: Option<&'a Path>,
    /// Scratch root the forge tmpfs is staged under (`EXTOS_FORGE_SCRATCH`).
    pub forge_scratch: &'a Path,
    /// `/var` + `/home` mount sources (PLAN 4.1.5). Defaults to no mounts.
    pub mounts: &'a MountSources,
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
    /// `forged` / `skipped` / `n/a` — the forge phase token, as recorded.
    pub forge: String,
    /// BLS entries the forge wrote or confirmed (0 when it did not run).
    pub bls_entries: usize,
    /// Orphan generation directories the sweep removed.
    pub reaped: Vec<u64>,
    /// Declared security applied to the roof (PLAN 6.2 glue): AppArmor
    /// profiles written, SELinux labels applied/refused.
    pub security: libextos::security::RoofSecurityReport,
    /// Services enabled by this apply (PLAN 7.2.2): declared services whose
    /// `multi-user.target.wants` symlink was created or confirmed.
    pub services_enabled: usize,
    /// Services disabled by this apply (PLAN 7.2.2): marker-recorded services
    /// that are no longer declared.
    pub services_disabled: usize,
}

/// Execute the full local pipeline for `system`.
///
/// Order (a failure never deletes the snapshot created before the weave):
/// 1. expand groups/virtual refs; 2. fetch+ingest missing refs; 3. plan;
/// 4. snapshot/prime `gen-<n>`; 5. weave; 6. seed `/etc` + reconcile declared
/// services (PLAN 7.2.2); 7. phantom rows; 8. `/var`+`/home` mounts;
/// 9. `ldconfig`/`depmod`; 10. runlevel-0 forge (initramfs + BLS matrix,
/// PLAN 4.2.6); 11. lockfile + generation record + `current` switch + orphan
/// sweep (PLAN 4.1.1 – 4.1.6).
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
    const STEPS: usize = 11;

    println!("[1/{STEPS}] expand {} (groups, virtual refs)", system.path.display());
    let expansion = system.expand(repo)?;
    for (group, count) in &expansion.groups {
        println!("        @{group} → {count} package(s)");
    }
    for (virtual_ref, reference) in &expansion.virtuals {
        println!("        {virtual_ref} → {}", reference.label());
    }
    for note in &expansion.notes {
        println!("        note: {note}");
    }
    let missing = probe_missing(repo, &expansion.refs);
    println!(
        "        {} expanded ref(s), {} present, {} missing",
        expansion.refs.len(),
        expansion.refs.len() - missing.len(),
        missing.len()
    );
    for reference in &missing {
        println!("        · {} is not in the CAS yet", reference.label());
    }

    println!("[2/{STEPS}] fetch missing packages");
    let fetched = fetch_missing(repo, &expansion.refs, opts.cache_dir)?;
    println!(
        "        {} fetched, {} already in the CAS",
        fetched,
        expansion.refs.len() - fetched
    );

    // Full evaluation needs every manifest, so it runs after the fetch step.
    println!("[3/{STEPS}] plan (reflink, origin priority, SONAME anchors)");
    let eval = evaluate_expanded(repo, system, expansion)?;
    let plan = &eval.plan;
    println!(
        "        {} node(s), {} edge(s), {} op(s) [dirs {}, files {}, symlinks {}, wrappers {}], collisions {}, anchors {}",
        eval.node_count(),
        eval.edges,
        plan.len(),
        plan.directory_ops(),
        plan.file_ops(),
        plan.symlink_ops(),
        plan.wrapper_ops(),
        plan.collisions().len(),
        plan.anchors().len()
    );
    for choice in plan.anchors().choices() {
        if !choice.losers().is_empty() {
            println!(
                "        anchor {} → {} (priority {}, over {})",
                choice.soname,
                choice.winner,
                choice.priority,
                choice.losers().join(", ")
            );
        }
    }

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

    println!("[6/{STEPS}] seed /etc from the woven packages");
    let seeded = seed_etc(repo, &eval.resolved, &snapshot.path)
        .context("/etc seeding failed")?;
    println!(
        "        {} seeded, {} kept (already present)",
        seeded.seeded.len(),
        seeded.skipped.len()
    );
    for warning in &seeded.warnings {
        println!("        ⚠ {warning}");
    }

    // PLAN 7.2.2: declarative service enable/disable (wants-dir reconcile).
    let services = reconcile_services(&snapshot.path, &eval.system.services)
        .context("service enable/disable failed")?;
    if services.relevant {
        println!(
            "        services: {} enabled, {} disabled, {} warning(s)",
            services.enabled,
            services.disabled,
            services.warnings.len()
        );
        for warning in &services.warnings {
            println!("        ⚠ {warning}");
        }
    } else {
        println!("        services: none declared");
    }

    println!("[7/{STEPS}] phantom rows");
    let phantom_rows = write_phantoms(repo, &eval, &snapshot.path)
        .context("phantom database generation failed")?;
    println!("        {phantom_rows} row(s) written");

    println!("[8/{STEPS}] /var + /home mounts");
    apply_roof_mounts(&snapshot.path, opts.mounts);

    println!("[9/{STEPS}] post-weave tools (ldconfig, depmod)");
    postprocess(&snapshot.path, eval.system.kernel.as_deref())?;

    // PLAN 6.2 glue: declared AppArmor profiles + SELinux labels for the roof.
    let roof_packages: Vec<libextos::security::RoofPackage> = eval
        .resolved
        .iter()
        .map(|r| libextos::security::RoofPackage {
            label: r.label(),
            hash: r.hash.clone(),
        })
        .collect();
    let security = libextos::security::apply_roof_security(repo, &roof_packages, &snapshot.path)
        .context("roof security pass failed")?;
    if !security.apparmor_profiles.is_empty() {
        println!(
            "        apparmor: {} profile(s) written [{}]",
            security.apparmor_profiles.len(),
            security.apparmor_profiles.join(", ")
        );
    }
    for skip in &security.apparmor_skipped {
        println!("        ⚠ apparmor skipped: {skip}");
    }
    if security.selinux_applied > 0 {
        println!("        selinux: {} file(s) labeled", security.selinux_applied);
    }
    for skip in &security.selinux_skipped {
        println!("        ⚠ selinux skipped: {skip}");
    }
    let security_quiet = security.apparmor_profiles.is_empty()
        && security.apparmor_skipped.is_empty()
        && security.selinux_applied == 0
        && security.selinux_skipped.is_empty();
    if security_quiet {
        println!("        security: nothing declared");
    }

    println!("[10/{STEPS}] runlevel-0 forge (initramfs + BLS)");
    let forge_report = run_forge_phase(repo, &eval, opts, number)?;

    println!("[11/{STEPS}] lockfile + generation record + orphan sweep");
    let lockfile = snapshot.path.join(".lock");
    let entries = resolve_locks(repo, &eval.expansion.refs)?;
    repo.write_lockfile(&entries, &lockfile)
        .with_context(|| format!("cannot write {}", lockfile.display()))?;
    let lock_bytes = fs::read(&lockfile)?;
    let lock_hash = hash_bytes(&lock_bytes, repo.algo);
    let forge_token = forge_report
        .as_ref()
        .map_or("n/a", |report| report.phase.summary())
        .to_string();
    let bls_entries = forge_report.as_ref().map_or(0, ForgeReport::bls_entries);
    tracker.record(
        number,
        Some(lock_hash),
        &format!(
            "instanz apply: {} package(s), forge={forge_token}, bls={bls_entries}",
            entries.len()
        ),
    )?;

    if forge_report.as_ref().is_some_and(|report| report.bls.is_some()) {
        println!("        BLS entries: written by the forge phase above");
    } else if opts.boot_root.is_some() {
        println!(
            "        BLS entries skipped: the forge produced no initramfs (its reason is printed above)"
        );
    } else if let Some(entries_dir) = opts.bls_dir {
        write_bls_entry(entries_dir, &eval.system, number)?;
        println!("        BLS entry {}/gen-{number}.conf", entries_dir.display());
    } else {
        println!(
            "        BLS entry skipped: neither --boot-root/EXTOS_BLS_ROOT nor EXTOS_BLS_DIR is set \
             (symlink-only mode)"
        );
    }

    engine
        .switch_to(number)
        .with_context(|| format!("cannot switch `current` to gen-{number}"))?;
    println!("        ✓ generation {number} is now current");

    let reap = reap_orphans(opts)?;

    println!(
        "✓ applied {} → {} ({} op(s), {} phantom row(s), forge {forge_token})",
        eval.system.name,
        snapshot.path.display(),
        execution.journal.len(),
        phantom_rows
    );

    let report = ApplyReport {
        generation: number,
        root: snapshot.path,
        plan_ops: execution.journal.len(),
        phantom_rows,
        lockfile,
        forge: forge_token,
        bls_entries,
        reaped: reap.removed,
        security,
        services_enabled: services.enabled,
        services_disabled: services.disabled,
    };
    println!(
        "        security: {} apparmor profile(s), {} selinux label(s), {} skipped",
        report.security.apparmor_profiles.len(),
        report.security.selinux_applied,
        report.security.apparmor_skipped.len() + report.security.selinux_skipped.len()
    );
    println!(
        "        services: {} enabled, {} disabled",
        report.services_enabled, report.services_disabled
    );

    Ok(report)
}

/// Run the runlevel-0 forge phase for the generation that was just woven.
///
/// `None` means "there was nothing to forge into": no boot root configured (or
/// the legacy `EXTOS_BLS_DIR` snapshot-entry mode). The reason is printed so an
/// operator never wonders why no initramfs appeared.
fn run_forge_phase(
    repo: &CasRepository,
    eval: &Evaluation,
    opts: &ApplyOptions<'_>,
    number: u64,
) -> anyhow::Result<Option<ForgeReport>> {
    let Some(boot_root) = opts.boot_root else {
        match opts.bls_dir {
            Some(entries) => println!(
                "        ⚠ forge skipped: EXTOS_BLS_DIR ({}) is the legacy snapshot-entry mode; \
                 set --boot-root/EXTOS_BLS_ROOT to forge an initramfs",
                entries.display()
            ),
            None => println!(
                "        ⚠ forge skipped: no boot root configured (--boot-root / EXTOS_BLS_ROOT)"
            ),
        }
        return Ok(None);
    };

    let labels: Vec<String> = eval.resolved.iter().map(ResolvedRef::label).collect();
    let packages: Vec<PackageSource<'_>> = eval
        .resolved
        .iter()
        .zip(&labels)
        .map(|(row, label)| PackageSource {
            label,
            hash: &row.hash,
        })
        .collect();

    let request = ForgeRequest {
        boot_root,
        scratch: opts.forge_scratch,
        generation: number,
        system: &eval.system.name,
        kernel: eval.system.kernel.as_deref(),
        modules: &eval.system.boot.modules,
        cmdline: eval.system.boot.cmdline.as_deref(),
        initrd: eval.system.boot.initrd.as_deref(),
        linux: eval.system.linux.as_deref(),
        packages: &packages,
    };
    let report = forge::run_forge(repo, &request)?;
    Ok(Some(report))
}

/// BLS entries directory the sweep must protect, whichever mode is configured.
fn configured_entries_dir(opts: &ApplyOptions<'_>) -> Option<PathBuf> {
    match (opts.boot_root, opts.bls_dir) {
        (Some(boot), _) => Some(bls_entries_dir(boot)),
        (None, Some(entries)) => Some(entries.to_path_buf()),
        (None, None) => None,
    }
}

/// Remove orphan generations, announcing every removal (never fatal).
fn reap_orphans(opts: &ApplyOptions<'_>) -> anyhow::Result<ReapReport> {
    let entries = configured_entries_dir(opts);
    let report = reaper::reap(opts.rootfs, entries.as_deref())?;
    for number in &report.removed {
        println!(
            "        ✓ reaped gen-{number} (orphan: no generation record, not current, no BLS entry)"
        );
    }
    for error in &report.errors {
        println!("        ✗ could not reap {error}");
    }
    if report.disabled {
        println!("        orphan sweep: {}", report.summary());
    } else {
        println!(
            "        orphan sweep: {} ({} referenced generation(s) protected)",
            report.summary(),
            report.referenced.len()
        );
    }
    Ok(report)
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

// ─── /etc seeding (PLAN 4.1.4) ──────────────────────────────────

/// One packaged file under `/etc` inside a CAS object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtcFile {
    /// Path relative to the roof root (`etc/…`).
    pub rel_path: PathBuf,
    /// Absolute source path inside the CAS object.
    pub source: PathBuf,
    /// Provider label, `origin/name`.
    pub provider: String,
    /// Whether the payload is a symlink (copied as a symlink, not dereferenced).
    pub is_symlink: bool,
}

/// A seeded-or-skipped `/etc` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedSkip {
    /// Path relative to the roof root.
    pub rel_path: PathBuf,
    /// Provider that shipped the file.
    pub provider: String,
    /// Why the file was not written (PLAN 4.1.4: never overwrite).
    pub reason: String,
}

/// Result of [`seed_etc`].
#[derive(Debug, Clone, Default)]
pub struct SeedOutcome {
    /// Files written into the roof's `etc`.
    pub seeded: Vec<PathBuf>,
    /// Files left untouched because the destination already existed.
    pub skipped: Vec<SeedSkip>,
    /// Operator-facing warnings, one per skip plus any unreadable payload.
    pub warnings: Vec<String>,
}

/// Enumerate the packaged files under `/etc` in one CAS object (PLAN 4.1.4).
///
/// Walks `objects/<hash>/content/etc/…` without following symlinks: an in-package
/// link is reported with `is_symlink` so seeding recreates the link instead of
/// copying its target. Directories are implicit (created by the caller).
pub fn etc_files_in_object(
    repo: &CasRepository,
    hash: &str,
    provider: &str,
) -> anyhow::Result<Vec<EtcFile>> {
    let etc_root = repo.object_path(hash).join("content").join("etc");
    let mut files = Vec::new();
    if !etc_root.is_dir() {
        return Ok(files);
    }
    let mut pending = vec![etc_root.clone()];
    while let Some(dir) = pending.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(anyhow::Error::new(err)
                    .context(format!("cannot read packaged {} under {}", dir.display(), hash)))
            }
        };
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                pending.push(path);
                continue;
            }
            let rel_path = path
                .strip_prefix(repo.object_path(hash).join("content"))
                .map_err(|_| anyhow!("packaged file {} escaped its object", path.display()))?
                .to_path_buf();
            files.push(EtcFile {
                rel_path,
                source: path,
                provider: provider.to_string(),
                is_symlink: file_type.is_symlink(),
            });
        }
    }
    files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    Ok(files)
}

/// Seed default `/etc` files from the woven packages into the roof (PLAN 4.1.4).
///
/// Conflict rule: a seeded file is written **only if the destination does not
/// exist**. An existing file is assumed to be edited or system-provided and is
/// never overwritten; the skip is recorded in [`SeedOutcome::skipped`] and a
/// warning is printed/logged. Symlinks shipped by a package are recreated as
/// symlinks so `etc/alternatives`-style layouts survive.
pub fn seed_etc(
    repo: &CasRepository,
    resolved: &[ResolvedRef],
    root: &Path,
) -> anyhow::Result<SeedOutcome> {
    let mut outcome = SeedOutcome::default();
    if !root.is_dir() {
        bail!("/etc seeding: roof root {} is not a directory", root.display());
    }

    for row in resolved {
        for file in etc_files_in_object(repo, &row.hash, &row.label())? {
            let destination = root.join(&file.rel_path);
            if destination.symlink_metadata().is_ok() {
                let reason = "destination already exists; kept (never overwritten)".to_string();
                outcome.warnings.push(format!(
                    "etc seed skipped {} ({}): {reason}",
                    file.rel_path.display(),
                    file.provider
                ));
                outcome.skipped.push(SeedSkip {
                    rel_path: file.rel_path,
                    provider: file.provider,
                    reason,
                });
                continue;
            }
            match seed_one(&file, &destination) {
                Ok(()) => outcome.seeded.push(file.rel_path),
                Err(err) => {
                    let reason = err.to_string();
                    outcome.warnings.push(format!(
                        "etc seed failed {} ({}): {reason}",
                        file.rel_path.display(),
                        file.provider
                    ));
                    outcome.skipped.push(SeedSkip {
                        rel_path: file.rel_path,
                        provider: file.provider,
                        reason,
                    });
                }
            }
        }
    }
    Ok(outcome)
}

/// Copy one packaged `/etc` file into place (parent directories created).
fn seed_one(file: &EtcFile, destination: &Path) -> anyhow::Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    if file.is_symlink {
        let target = fs::read_link(&file.source)
            .with_context(|| format!("cannot read link {}", file.source.display()))?;
        std::os::unix::fs::symlink(&target, destination).with_context(|| {
            format!(
                "cannot seed link {} → {}",
                destination.display(),
                target.display()
            )
        })?;
    } else {
        fs::copy(&file.source, destination).with_context(|| {
            format!(
                "cannot seed {} from {}",
                destination.display(),
                file.source.display()
            )
        })?;
    }
    Ok(())
}

// ─── Service enable/disable (PLAN 7.2.2) ────────────────────────

/// Marker file (relative to the roof root) recording the service set the
/// apply pipeline reconciles: `etc/systemd/.extos-enabled-services`.
///
/// # Contract
///
/// The marker is the *only* bookkeeping `instanz apply` owns inside the
/// roof's `multi-user.target.wants` directory, and it makes apply touch
/// **only** symlinks it created itself:
///
/// * On every apply, exactly the `wants/<name>.service` symlinks recorded in
///   the marker whose name is no longer declared are removed, then the marker
///   is rewritten (sorted, one name per line, byte-identical for an unchanged
///   set) with the services this apply is responsible for: the declared set
///   minus entries found operator-owned.
/// * Symlinks that are **not** marker-recorded belong to the operator or to
///   other tooling (e.g. `systemctl enable`): they are never removed, and a
///   declared service whose wants entry already exists with a different
///   target is left untouched with a warning instead of being clobbered —
///   and it is *not* recorded, so a later apply can never delete it either.
/// * A declared service whose unit file is missing is recorded without a
///   symlink (it is warned about honestly), so a later apply that stops
///   declaring it still sweeps the wants directory clean.
///
/// The marker lives inside the generation tree, so the disable semantics
/// travel with snapshots: a generation that stops declaring a service loses
/// the symlink, exactly like every other declarative bit.
pub const ENABLED_SERVICES_MARKER: &str = "etc/systemd/.extos-enabled-services";

/// Result of the PLAN 7.2.2 service reconcile pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceReconcileReport {
    /// Declared services whose `multi-user.target.wants` symlink this apply
    /// created or confirmed.
    pub enabled: usize,
    /// Marker-recorded services that are no longer declared (symlink removed,
    /// or already absent).
    pub disabled: usize,
    /// Honest warnings: declared services without a unit file in the roof,
    /// operator-owned wants entries left untouched.
    pub warnings: Vec<String>,
    /// Whether anything was reconciled at all (`services` declared or the
    /// marker exists). A roof with neither gets a single honest
    /// "none declared" line and no invented `etc/systemd` tree.
    pub relevant: bool,
}

/// Validate a declared service name for path-safe use under
/// `etc/systemd/system/multi-user.target.wants/` (systemd template
/// instances keep their `@`, e.g. `sshd@console`).
fn validate_service_name(service: &str) -> anyhow::Result<()> {
    let ok = !service.is_empty()
        && !service.contains("..")
        && service
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'));
    if ok {
        Ok(())
    } else {
        bail!(
            "invalid service name {service:?}: expected non-empty [a-zA-Z0-9._@-] without '..'"
        )
    }
}

/// Relative `multi-user.target.wants` symlink target for `<name>.service`,
/// pointing at the FHS packaged-unit location `/usr/lib/systemd/system`
/// *inside the same roof* (the roof root is four levels up from the wants
/// directory). Relative targets survive roof relocation, exactly like the
/// relative targets the weaver and the CAS virtual links use.
fn wants_symlink_target(service: &str) -> String {
    format!("../../../../usr/lib/systemd/system/{service}.service")
}

/// Locate `<name>.service` in the roof's standard systemd unit search path:
/// `etc/systemd/system` (pipeline/operator units) first, then
/// `usr/lib/systemd/system` — the FHS location the weaver places packaged
/// units at. Existence is checked without dereferencing: a woven unit is
/// often a symlink into the generation's payload.
fn unit_in_roof(root: &Path, service: &str) -> Option<PathBuf> {
    ["etc/systemd/system", "usr/lib/systemd/system"]
        .iter()
        .map(|dir| root.join(dir).join(format!("{service}.service")))
        .find(|path| path.symlink_metadata().is_ok())
}

/// Synchronize the roof's declarative service set (PLAN 7.2.2).
///
/// For every name in `declared`,
/// `<roof>/etc/systemd/system/multi-user.target.wants/<name>.service` is
/// created as a *relative* symlink to the roof's
/// `/usr/lib/systemd/system/<name>.service` — but only when the unit file
/// exists in the roof's standard unit search path; a declared service whose
/// unit is absent anywhere in the roof (its package is not woven) is an
/// honest warning, not a failure. Previously enabled services that are no
/// longer declared are disabled. See [`ENABLED_SERVICES_MARKER`] for the
/// full marker contract and why non-marker-recorded symlinks are untouchable.
///
/// A roof with no declared services and no marker is left completely
/// untouched (no `etc/systemd` tree is invented for it).
pub fn reconcile_services(
    root: &Path,
    declared: &[String],
) -> anyhow::Result<ServiceReconcileReport> {
    for service in declared {
        validate_service_name(service)?;
    }
    // [`ENABLED_SERVICES_MARKER`] is the marker path relative to the roof
    // root; its parent is the systemd directory the wants tree hangs off.
    let marker = root.join(ENABLED_SERVICES_MARKER);
    let Some(systemd_dir) = marker.parent() else {
        bail!("service marker {} has no parent directory", marker.display());
    };
    let wants_dir = systemd_dir.join("system").join("multi-user.target.wants");

    let previous: Vec<String> = match fs::read_to_string(&marker) {
        Ok(text) => text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(err) => {
            return Err(anyhow::Error::new(err).context(format!(
                "cannot read service enable marker {}",
                marker.display()
            )))
        }
    };

    let mut declared_sorted = declared.to_vec();
    declared_sorted.sort();
    declared_sorted.dedup();

    if declared_sorted.is_empty() && previous.is_empty() {
        return Ok(ServiceReconcileReport::default());
    }

    let mut report = ServiceReconcileReport {
        relevant: true,
        ..Default::default()
    };

    // Disable pass: marker-recorded services that are no longer declared.
    for name in &previous {
        if declared_sorted.binary_search(name).is_ok() {
            continue;
        }
        let link = wants_dir.join(format!("{name}.service"));
        match fs::remove_file(&link) {
            Ok(()) => {}
            // A marker-recorded service can legitimately have no symlink
            // (its unit was missing when it was last declared).
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(anyhow::Error::new(err).context(format!(
                    "cannot remove service enable symlink {}",
                    link.display()
                )))
            }
        }
        report.disabled += 1;
    }

    // Enable pass: declared services get a relative wants-dir symlink.
    let mut operator_owned: Vec<String> = Vec::new();
    for name in &declared_sorted {
        if unit_in_roof(root, name).is_none() {
            report.warnings.push(format!(
                "service {name}: declared but its unit file does not exist anywhere in the \
                 roof's unit search path (etc/systemd/system/{name}.service and \
                 usr/lib/systemd/system/{name}.service are both absent) — not enabled; \
                 is its package woven?"
            ));
            continue;
        }
        let link = wants_dir.join(format!("{name}.service"));
        let target = wants_symlink_target(name);
        match fs::symlink_metadata(&link) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(&wants_dir)
                    .with_context(|| format!("cannot create {}", wants_dir.display()))?;
                std::os::unix::fs::symlink(&target, &link).with_context(|| {
                    format!("cannot enable service {name}: {} → {target}", link.display())
                })?;
            }
            Err(err) => {
                return Err(anyhow::Error::new(err).context(format!(
                    "cannot inspect service enable symlink {}",
                    link.display()
                )))
            }
            Ok(meta) if meta.file_type().is_symlink() => {
                let existing = fs::read_link(&link).with_context(|| {
                    format!("cannot read service enable symlink {}", link.display())
                })?;
                if existing != Path::new(&target) {
                    // Operator- or tooling-owned entry (e.g. `systemctl
                    // enable`): never clobbered, never marker-recorded, and
                    // therefore never removed by a later apply.
                    report.warnings.push(format!(
                        "service {name}: {} already exists with target {} — left untouched \
                         (operator-owned; not marker-recorded)",
                        link.display(),
                        existing.display()
                    ));
                    operator_owned.push(name.clone());
                    continue;
                }
            }
            Ok(_) => {
                report.warnings.push(format!(
                    "service {name}: {} exists and is not a symlink — left untouched \
                     (operator-owned; not marker-recorded)",
                    link.display()
                ));
                operator_owned.push(name.clone());
                continue;
            }
        }
        report.enabled += 1;
    }

    // Marker rewrite: the declared set minus operator-owned entries, sorted,
    // one per line — byte-identical when the set did not change.
    fs::create_dir_all(&systemd_dir)
        .with_context(|| format!("cannot create {}", systemd_dir.display()))?;
    let mut content = String::new();
    for name in &declared_sorted {
        if operator_owned.contains(name) {
            continue;
        }
        content.push_str(name);
        content.push('\n');
    }
    fs::write(&marker, content)
        .with_context(|| format!("cannot write service enable marker {}", marker.display()))?;

    Ok(report)
}

// ─── Mounts wiring (PLAN 4.1.5) ─────────────────────────────────

/// Assemble and (when permitted) apply the roof's `/var` + `/home` mounts.
///
/// Never fails the apply: a capability skip is announced with its reason and the
/// spec list is printed so the operator can run the mounts later. Returns the
/// outcome so callers/tests can assert it.
fn apply_roof_mounts(root: &Path, sources: &MountSources) -> MountOutcome {
    let specs = plan_mounts(root, sources);
    let capability = probe_mount_capability();
    if specs.is_empty() {
        println!("        no mount sources declared (var/home stay generation-local)");
        return MountOutcome::default();
    }
    if let Some(reason) = capability.reason() {
        println!("        mounts not applied: {reason}");
    }
    let outcome = apply_mounts(&specs, &capability, &HostMountRunner);
    for spec in &outcome.applied {
        println!("        ✓ mounted {}", spec.label());
    }
    for skip in &outcome.skipped {
        println!("        ⚠ skipped {}: {}", skip.spec.label(), skip.reason);
    }
    for failure in &outcome.failed {
        println!("        ✗ failed {}: {}", failure.spec.label(), failure.reason);
    }
    if outcome.all_applied() && !outcome.applied.is_empty() {
        println!("        ✓ all {} mount(s) applied", outcome.applied.len());
    }
    outcome
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
///
/// Two boot-entry layouts are understood, mirroring `apply`:
///
/// * `boot_root` (`--boot-root` / `EXTOS_BLS_ROOT`): point `loader.conf` at the
///   forge matrix entry `extos-<system>-g<n>-<kernel>.conf` for the generation.
///   If the forge never wrote one (skipped, or no `linux = "…"`), the default
///   is left alone with a printed reason rather than pointing at a missing file.
/// * `bls_dir` (`EXTOS_BLS_DIR`): the Phase-2 snapshot layout, whose entry is
///   always `gen-<n>.conf`.
pub fn rollback(
    rootfs: &Path,
    target: RollbackTarget,
    boot_root: Option<&Path>,
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

    match (boot_root, bls_dir) {
        (Some(boot), _) => {
            let entries = bls_entries_dir(boot);
            match bls_entry_for_generation(&entries, target_number) {
                Some(id) => {
                    let conf = set_loader_default(boot, &id)?;
                    println!("  BLS default {} → {id}", conf.display());
                }
                None => println!(
                    "  BLS default skipped: no forge entry for gen-{target_number} under {}",
                    entries.display()
                ),
            }
        }
        (None, Some(dir)) => {
            let conf = set_bls_default(dir, target_number)?;
            println!("  BLS default {} → {}", conf.display(), BlsEntry::file_name(target_number));
        }
        (None, None) => println!("  BLS default skipped: EXTOS_BLS_DIR is not set (symlink-only mode)"),
    }

    Ok(target_number)
}

/// **Id** (file stem) of the BLS entry in `entries_dir` that belongs to `generation`.
///
/// Both layouts are accepted (`gen-<n>.conf` and the forge matrix
/// `extos-<system>-g<n>-<kernel>.conf`); the lexicographically first match wins
/// so a rollback is deterministic when several kernels carry the generation.
/// The `.conf` suffix is stripped because `loader.conf` (`BlsPlan::write` and
/// `set_loader_default`) names entries by id, not by file name.
fn bls_entry_for_generation(entries_dir: &Path, generation: u64) -> Option<String> {
    let mut matches: Vec<String> = fs::read_dir(entries_dir)
        .ok()?
        .flatten()
        .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
        .filter(|name| reaper::generation_from_entry_name(name) == Some(generation))
        .filter_map(|name| name.strip_suffix(".conf").map(str::to_string))
        .collect();
    matches.sort();
    matches.into_iter().next()
}

/// Remove forge matrix entries (`extos-…-g<n>-….conf`) for collected generations.
///
/// [`generation::gc_with_entries`] only knows the `gen-<n>.conf` snapshot shape;
/// the forge matrix has one file per (system, kernel), so every file whose
/// decoded generation was collected is removed. Missing entries are not errors.
fn remove_forge_entries(entries_dir: &Path, removed: &[u64]) -> Vec<String> {
    if removed.is_empty() {
        return Vec::new();
    }
    let Ok(entries) = fs::read_dir(entries_dir) else {
        return Vec::new();
    };
    let mut errors = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.starts_with("extos-") {
            continue;
        }
        let Some(number) = reaper::generation_from_entry_name(name) else {
            continue;
        };
        if !removed.contains(&number) {
            continue;
        }
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => errors.push(format!("{}: {error}", path.display())),
        }
    }
    errors
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
    boot_root: Option<&Path>,
    bls_dir: Option<&Path>,
) -> anyhow::Result<GcReport> {
    println!("stage 1/2: generations (keep {keep})");
    let engine = SnapshotEngine::open(rootfs)
        .with_context(|| format!("cannot open generations root {}", rootfs.display()))?;
    let mut tracker = GenerationTracker::open(rootfs)?;
    let entries = boot_root
        .map(bls_entries_dir)
        .or_else(|| bls_dir.map(Path::to_path_buf));
    let generation_result =
        generation::gc_with_entries(&engine, &mut tracker, keep, entries.as_deref());

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
            // The forge matrix is per (system, kernel): `gc_with_entries` cannot
            // know those file names, so they are pruned here.
            if let Some(dir) = &entries {
                for error in remove_forge_entries(dir, &removed) {
                    eprintln!("  warning: could not remove forge BLS entry {error}");
                }
            }
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
    fn rollback_in_boot_root_mode_defaults_to_the_forge_matrix_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("system");
        let boot = tmp.path().join("boot");
        let entries = bls_entries_dir(&boot);
        fs::create_dir_all(&entries).unwrap();

        let engine = SnapshotEngine::open(&rootfs).unwrap();
        engine.create_empty(1).unwrap();
        engine.create_empty(2).unwrap();
        engine.switch_to(2).unwrap();
        let mut tracker = GenerationTracker::open(&rootfs).unwrap();
        tracker.record(1, None, "first").unwrap();
        tracker.record(2, None, "second").unwrap();

        fs::write(
            entries.join("extos-fixture-g1-6.11.0-extos.conf"),
            "title gen one\n",
        )
        .unwrap();
        fs::write(
            entries.join("extos-fixture-g2-6.11.0-extos.conf"),
            "title gen two\n",
        )
        .unwrap();

        let target = rollback(&rootfs, RollbackTarget::Previous, Some(&boot), None).unwrap();
        assert_eq!(target, 1);
        assert_eq!(engine.current_generation().unwrap(), Some(1));
        let loader = fs::read_to_string(boot.join("loader/loader.conf")).unwrap();
        assert_eq!(loader, "default extos-fixture-g1-6.11.0-extos\n");
    }

    #[test]
    fn forge_entries_are_pruned_only_for_collected_generations() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("loader/entries")).unwrap();
        let entries = tmp.path().join("loader/entries");
        for name in [
            "extos-fixture-g1-6.11.0-extos.conf",
            "extos-fixture-g2-6.11.0-extos.conf",
            "extos-fixture-g1-6.6.1-lts.conf",
            "gen-1.conf",
            "notes.txt",
        ] {
            fs::write(entries.join(name), "x\n").unwrap();
        }

        let errors = remove_forge_entries(&entries, &[1]);
        assert!(errors.is_empty(), "{errors:?}");
        // Both kernels of the collected generation are gone…
        assert!(!entries.join("extos-fixture-g1-6.11.0-extos.conf").exists());
        assert!(!entries.join("extos-fixture-g1-6.6.1-lts.conf").exists());
        // …everything else (other generation, legacy entry, unrelated file) stays.
        assert!(entries.join("extos-fixture-g2-6.11.0-extos.conf").exists());
        assert!(entries.join("gen-1.conf").exists());
        assert!(entries.join("notes.txt").exists());

        // Missing directory / empty removal list are not errors.
        assert!(remove_forge_entries(&tmp.path().join("absent"), &[1]).is_empty());
        assert!(remove_forge_entries(&entries, &[]).is_empty());
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

    // ── 4.1.4 /etc seeding ─────────────────────────────────────

    /// Publish a fixture package with the given `(rel path, contents)` files.
    fn publish_fixture(
        repo: &CasRepository,
        origin: &str,
        name: &str,
        files: &[(&str, &str)],
    ) -> ResolvedRef {
        let staging = tempfile::tempdir().unwrap();
        let src = staging.path().join(name);
        fs::create_dir_all(&src).unwrap();
        for (rel, contents) in files {
            let path = src.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }
        let hash = repo.store_directory(&src).unwrap();
        repo.write_manifest(
            &hash,
            &format!(
                "{{ identity = {{ origin = \"{origin}\"; name = \"{name}\"; version = \"1.0\"; }}; }}"
            ),
        )
        .unwrap();
        repo.create_ref(origin, name, "1.0", &hash).unwrap();
        ResolvedRef {
            reference: CasRef::new(origin, name, "1.0"),
            version: "1.0".to_string(),
            hash,
            deps: 0,
        }
    }

    #[test]
    fn etc_files_are_enumerated_from_the_cas() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = CasRepository::open(tmp.path().join("repo"), HashAlgorithm::Blake3).unwrap();
        let row = publish_fixture(
            &repo,
            "debian",
            "base-files",
            &[
                ("etc/issue", "welcome\n"),
                ("etc/ssh/sshd_config", "Port 22\n"),
                ("usr/bin/hello", "#!/bin/sh\n"),
            ],
        );

        let files = etc_files_in_object(&repo, &row.hash, &row.label()).unwrap();
        let paths: Vec<&Path> = files.iter().map(|f| f.rel_path.as_path()).collect();
        assert_eq!(
            paths,
            vec![Path::new("etc/issue"), Path::new("etc/ssh/sshd_config")]
        );
        assert!(files.iter().all(|f| f.provider == "debian/base-files"));
        assert!(files.iter().all(|f| !f.is_symlink));

        // A package without /etc contributes nothing (not an error).
        let row = publish_fixture(&repo, "debian", "bin-only", &[("usr/bin/x", "x")]);
        assert!(etc_files_in_object(&repo, &row.hash, &row.label())
            .unwrap()
            .is_empty());
        // A missing object is empty too, not a panic.
        assert!(etc_files_in_object(&repo, "does-not-exist", "x/y")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn seeding_writes_absent_files_and_never_overwrites() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = CasRepository::open(tmp.path().join("repo"), HashAlgorithm::Blake3).unwrap();
        let a = publish_fixture(
            &repo,
            "debian",
            "base-files",
            &[
                ("etc/issue", "debian issue\n"),
                ("etc/profile.d/extos.sh", "export EXTOS=1\n"),
            ],
        );
        let b = publish_fixture(
            &repo,
            "archlinux",
            "filesystem",
            &[("etc/issue", "arch issue\n"), ("etc/hosts", "127.0.0.1 localhost\n")],
        );

        let roof = tmp.path().join("roof");
        fs::create_dir_all(roof.join("etc")).unwrap();
        // The operator already edited /etc/issue.
        fs::write(roof.join("etc/issue"), "hand-edited\n").unwrap();

        let outcome = seed_etc(&repo, &[a, b], &roof).unwrap();

        // The edited file is untouched.
        assert_eq!(
            fs::read_to_string(roof.join("etc/issue")).unwrap(),
            "hand-edited\n"
        );
        // Its two packaged claims are both recorded as skips.
        let skipped: Vec<&Path> = outcome.skipped.iter().map(|s| s.rel_path.as_path()).collect();
        assert!(skipped.contains(&Path::new("etc/issue")), "{skipped:?}");
        assert_eq!(
            outcome
                .skipped
                .iter()
                .filter(|s| s.rel_path == Path::new("etc/issue"))
                .count(),
            2,
            "both providers must be reported"
        );
        assert!(outcome.skipped.iter().all(|s| s.reason.contains("never overwritten")));
        assert_eq!(outcome.warnings.len(), outcome.skipped.len());

        // Absent files are seeded with their packaged contents.
        assert_eq!(
            fs::read_to_string(roof.join("etc/profile.d/extos.sh")).unwrap(),
            "export EXTOS=1\n"
        );
        assert_eq!(
            fs::read_to_string(roof.join("etc/hosts")).unwrap(),
            "127.0.0.1 localhost\n"
        );
        assert_eq!(outcome.seeded.len(), 2);
    }

    #[test]
    fn seeding_recreates_packaged_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = CasRepository::open(tmp.path().join("repo"), HashAlgorithm::Blake3).unwrap();
        let row = publish_fixture(&repo, "debian", "mime-support", &[]);
        // Inject a packaged symlink, which `store_directory` would have copied
        // as a regular file (it dereferences links).
        let link = repo.object_path(&row.hash).join("content/etc/mime.types");
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink("../usr/share/mime/types", &link).unwrap();

        let roof = tmp.path().join("roof");
        fs::create_dir_all(&roof).unwrap();
        let outcome = seed_etc(&repo, &[row], &roof).unwrap();
        assert!(outcome.seeded.contains(&PathBuf::from("etc/mime.types")));
        // Seeded as a symlink, not as a copy of its target.
        assert_eq!(
            fs::read_link(roof.join("etc/mime.types")).unwrap(),
            PathBuf::from("../usr/share/mime/types")
        );
        // Seeding a link does not materialize its target.
        assert!(!roof.join("usr/share/mime/types").exists());
    }

    #[test]
    fn seeding_requires_an_existing_roof() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = CasRepository::open(tmp.path().join("repo"), HashAlgorithm::Blake3).unwrap();
        let err = seed_etc(&repo, &[], &tmp.path().join("absent")).unwrap_err();
        assert!(err.to_string().contains("not a directory"), "{err}");
    }

    // ── 7.2.2 service enable/disable ───────────────────────────

    /// A roof whose woven tree ships the given `<name>.service` units.
    fn roof_with_units(services: &[&str]) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let unit_dir = tmp.path().join("usr/lib/systemd/system");
        for name in services {
            let unit = unit_dir.join(format!("{name}.service"));
            fs::create_dir_all(unit.parent().unwrap()).unwrap();
            fs::write(unit, "[Unit]\nDescription=stub\n").unwrap();
        }
        tmp
    }

    #[test]
    fn service_reconcile_enables_declared_services_with_relative_symlinks() {
        let tmp = roof_with_units(&["sshd"]);
        let roof = tmp.path();

        let report = reconcile_services(roof, &["sshd".to_string()]).unwrap();
        assert!(report.relevant);
        assert_eq!(report.enabled, 1);
        assert_eq!(report.disabled, 0);
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);

        let link = roof
            .join("etc/systemd/system/multi-user.target.wants")
            .join("sshd.service");
        assert_eq!(
            fs::read_link(&link).unwrap(),
            Path::new("../../../../usr/lib/systemd/system/sshd.service"),
            "the wants symlink must be relative and resolve inside the same roof"
        );
        // The relative target really lands on the woven unit.
        assert!(link.is_file());
        assert_eq!(
            fs::read_to_string(roof.join(ENABLED_SERVICES_MARKER)).unwrap(),
            "sshd\n"
        );
    }

    #[test]
    fn service_reconcile_rerun_is_idempotent() {
        let tmp = roof_with_units(&["sshd"]);
        let roof = tmp.path();

        let first = reconcile_services(roof, &["sshd".to_string()]).unwrap();
        let link = roof
            .join("etc/systemd/system/multi-user.target.wants")
            .join("sshd.service");
        let target_before = fs::read_link(&link).unwrap();
        let marker_before = fs::read_to_string(roof.join(ENABLED_SERVICES_MARKER)).unwrap();

        let second = reconcile_services(roof, &["sshd".to_string()]).unwrap();
        assert_eq!(second.enabled, first.enabled);
        assert_eq!(second.disabled, 0);
        assert!(second.warnings.is_empty(), "{:?}", second.warnings);
        assert_eq!(fs::read_link(&link).unwrap(), target_before, "link untouched");
        assert_eq!(
            fs::read_to_string(roof.join(ENABLED_SERVICES_MARKER)).unwrap(),
            marker_before,
            "marker rewrite is byte-identical"
        );
    }

    #[test]
    fn service_reconcile_disables_only_marker_recorded_services() {
        let tmp = roof_with_units(&["sshd", "chronyd"]);
        let roof = tmp.path();
        reconcile_services(roof, &["chronyd".to_string(), "sshd".to_string()]).unwrap();

        // An operator-owned entry (absolute target, like `systemctl enable`
        // writes) that apply must never touch — it is not marker-recorded.
        let wants = roof.join("etc/systemd/system/multi-user.target.wants");
        fs::create_dir_all(&wants).unwrap();
        std::os::unix::fs::symlink(
            "/usr/lib/systemd/system/nginx.service",
            wants.join("nginx.service"),
        )
        .unwrap();

        // chronyd is dropped from the declarations; sshd stays.
        let report = reconcile_services(roof, &["sshd".to_string()]).unwrap();
        assert_eq!(report.enabled, 1);
        assert_eq!(report.disabled, 1);
        assert!(!wants.join("chronyd.service").exists(), "marker-recorded removal");
        assert!(wants.join("sshd.service").exists());
        assert!(
            wants.join("nginx.service").symlink_metadata().is_ok(),
            "operator-owned symlink must survive"
        );
        assert_eq!(
            fs::read_to_string(roof.join(ENABLED_SERVICES_MARKER)).unwrap(),
            "sshd\n"
        );

        // Declaring nothing disables the rest — and still not the operator's.
        let report = reconcile_services(roof, &[]).unwrap();
        assert_eq!(report.enabled, 0);
        assert_eq!(report.disabled, 1);
        assert!(!wants.join("sshd.service").exists());
        assert!(
            wants.join("nginx.service").symlink_metadata().is_ok(),
            "operator-owned symlink must survive"
        );
        assert_eq!(fs::read_to_string(roof.join(ENABLED_SERVICES_MARKER)).unwrap(), "");
    }

    #[test]
    fn service_reconcile_warns_for_missing_units() {
        let tmp = roof_with_units(&[]);
        let roof = tmp.path();

        let report = reconcile_services(roof, &["ghost".to_string()]).unwrap();
        assert!(report.relevant);
        assert_eq!(report.enabled, 0);
        assert_eq!(report.disabled, 0);
        assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
        assert!(
            report.warnings[0].contains("ghost") && report.warnings[0].contains("does not exist"),
            "{:?}",
            report.warnings
        );
        assert!(
            !roof
                .join("etc/systemd/system/multi-user.target.wants/ghost.service")
                .exists(),
            "no symlink without a unit"
        );
        // Recorded (warned) so a later apply that stops declaring the service
        // still sweeps the wants directory; no symlink exists to remove.
        assert_eq!(
            fs::read_to_string(roof.join(ENABLED_SERVICES_MARKER)).unwrap(),
            "ghost\n"
        );

        let report = reconcile_services(roof, &[]).unwrap();
        assert_eq!(report.disabled, 1, "the warned service is cleanly swept");
        assert_eq!(fs::read_to_string(roof.join(ENABLED_SERVICES_MARKER)).unwrap(), "");
    }

    #[test]
    fn service_reconcile_is_a_noop_without_declarations_and_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let roof = tmp.path().join("fresh-roof");
        fs::create_dir_all(&roof).unwrap();

        let report = reconcile_services(&roof, &[]).unwrap();
        assert!(!report.relevant);
        assert_eq!(report.enabled, 0);
        assert_eq!(report.disabled, 0);
        assert!(report.warnings.is_empty());
        assert!(
            !roof.join(ENABLED_SERVICES_MARKER).exists(),
            "no marker may be invented for a service-less roof"
        );
        assert!(!roof.join("etc/systemd").exists(), "no etc/systemd tree invented");
    }

    #[test]
    fn service_reconcile_rejects_hostile_names() {
        let tmp = roof_with_units(&[]);
        for bad in ["../evil", "", "a/b", "sshd\n", "..", "sp ace"] {
            let err = reconcile_services(tmp.path(), &[bad.to_string()]).unwrap_err();
            assert!(
                err.to_string().contains("invalid service name"),
                "{bad:?}: {err}"
            );
        }
    }

    // ── 4.1.6 post-weave hooks ─────────────────────────────────

    /// Serializes the tests that mutate tool-override environment variables.
    static HOOK_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn write_stub(dir: &Path, name: &str, log: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        // Every invocation appends its argv to `log`, then succeeds.
        fs::write(
            &path,
            format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n", log.display()),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn orchestrating_flow_invokes_ldconfig_and_depmod_stubs() {
        let _guard = HOOK_ENV.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let roof = tmp.path().join("roof");
        fs::create_dir_all(roof.join("usr/lib")).unwrap();

        let ldconfig_log = tmp.path().join("ldconfig.log");
        let depmod_log = tmp.path().join("depmod.log");
        let ldconfig = write_stub(tmp.path(), "ldconfig-stub", &ldconfig_log);
        let depmod = write_stub(tmp.path(), "depmod-stub", &depmod_log);

        // SAFETY: guarded by HOOK_ENV; no other test reads these variables.
        unsafe {
            std::env::set_var("EXTOS_LDCONFIG", &ldconfig);
            std::env::set_var("EXTOS_DEPMOD", &depmod);
        }
        let result = postprocess(&roof, Some("6.8.2-extos"));
        unsafe {
            std::env::remove_var("EXTOS_LDCONFIG");
            std::env::remove_var("EXTOS_DEPMOD");
        }
        result.unwrap();

        let ldconfig_args = fs::read_to_string(&ldconfig_log).unwrap();
        assert_eq!(
            ldconfig_args.trim(),
            format!("-r {}", roof.display()),
            "ldconfig must be chroot-scoped to the woven roof"
        );
        let depmod_args = fs::read_to_string(&depmod_log).unwrap();
        assert_eq!(
            depmod_args.trim(),
            format!("-b {} 6.8.2-extos", roof.display())
        );
    }

    #[test]
    fn depmod_is_explicitly_skipped_without_a_kernel() {
        let _guard = HOOK_ENV.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let roof = tmp.path().join("roof");
        fs::create_dir_all(roof.join("usr/lib")).unwrap();

        let ldconfig_log = tmp.path().join("ldconfig.log");
        let depmod_log = tmp.path().join("depmod.log");
        let ldconfig = write_stub(tmp.path(), "ldconfig-stub", &ldconfig_log);
        let depmod = write_stub(tmp.path(), "depmod-stub", &depmod_log);
        unsafe {
            std::env::set_var("EXTOS_LDCONFIG", &ldconfig);
            std::env::set_var("EXTOS_DEPMOD", &depmod);
        }
        let result = postprocess(&roof, None);
        unsafe {
            std::env::remove_var("EXTOS_LDCONFIG");
            std::env::remove_var("EXTOS_DEPMOD");
        }
        result.unwrap();

        assert!(ldconfig_log.exists(), "ldconfig still runs");
        assert!(!depmod_log.exists(), "depmod must not run without a kernel");
    }
}
