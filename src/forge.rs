//! Runlevel-0 initramfs forge *trigger* for `instanz apply` (PLAN 4.2.6, T1).
//!
//! Wave 1 delivered the forge stack in `libextos::forge` (blueprint parser,
//! tmpfs namespace, `mkinitcpio` bridge, BLS matrix). This module is the
//! `instanz`-side glue that makes `apply` actually *use* it: derive a blueprint
//! from the system config, run the generator inside the forge, and publish the
//! bootloader entries — or say precisely why it cannot, without failing the
//! apply.
//!
//! # Why the blueprint is *derived* (documented derivation)
//!
//! `system.nix` (see [`crate::system`]) has no `forge` block: the Phase-4
//! grammar carries `boot = { kernel; modules; cmdline; initrd; }`. The Forge
//! blueprint grammar (PLAN 4.2.1) is a *different* document (`tools`, `hooks`,
//! `output`). Rather than asking operators to write two files, `apply` maps the
//! boot block onto a blueprint with these rules:
//!
//! | Blueprint field | Derived from |
//! |-----------------|--------------|
//! | `tools[0]` | the first woven package (declaration order) whose CAS payload ships an **executable** `mkinitcpio` at `usr/bin/`, `bin/`, `usr/sbin/` or `sbin/` |
//! | `hooks` | the baseline set `base udev modconf block filesystems`, then `boot.modules` in declaration order |
//! | `output.dir` | the caller's boot root (`--boot-root` / `EXTOS_BLS_ROOT`) — never a hardcoded `/boot` |
//! | `output.name` | `boot.initrd`'s file name when declared, else `initramfs-linux.img` |
//! | `output.kernel` | `boot.kernel`, else the top-level `kernel` alias |
//!
//! ## Known limitations of the derivation (honest notes)
//!
//! * **`boot.modules` ride in `HOOKS=(…)`.** The wave-1 `mkinitcpio` bridge
//!   renders `MODULES=()` unconditionally, so there is no field to put early
//!   modules in. Appending them to the hook list is what "modules as hooks"
//!   means today; a real `mkinitcpio` warns about hooks it cannot find and
//!   continues. When the bridge gains `MODULES` support (a `libextos` change,
//!   not an `instanz` one) the derivation must move them there.
//! * **The generator always comes from the CAS**, so the tool that runs is the
//!   one the system actually ships (no host-version leakage). The bridge still
//!   honours `EXTOS_MKINITCPIO` for callers that build their own blueprint, but
//!   the derived blueprint names an in-CAS tool and that wins.
//! * **No extra binds are derived.** A host path outside `/usr`, `/bin`,
//!   `/sbin`, `/lib`, `/lib64` (or `EXTOS_FORGE_HOST_DIRS`) is not visible
//!   inside the forge; deriving binds from host paths would bake a host layout
//!   into the blueprint, which the project forbids.
//!
//! # Failure policy (documented)
//!
//! | Situation | Effect on `apply` |
//! |-----------|-------------------|
//! | no woven package ships `mkinitcpio` | [`ForgePhase::Skipped`] — loud line, generation records `forge=skipped` |
//! | generator binary not resolvable | `Skipped` — same |
//! | unprivileged user/mount namespaces unavailable | `Skipped` — same (host limitation, not a config error) |
//! | blueprint/derivation invalid, generator exits non-zero, artifact missing, BLS id collision | **fatal** typed error — `apply` fails after the snapshot exists (rollback keeps working) |
//! | no `linux = "…"` boot image declared | image is forged, BLS entry is skipped with a printed reason |
//!
//! A skipped forge never writes an artifact and never writes BLS entries: a
//! bootloader entry pointing at an initramfs that was not produced would be a
//! lie.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use libextos::cas::CasRepository;
use libextos::forge::ForgeError;
use libextos::forge::bls::{
    BlsPlan, BlsPlanOptions, BlsReport, BlsSystem, BlsWriteOptions, BootKernel, LoaderConfAction,
};
use libextos::forge::blueprint::{ForgeBlueprint, ForgeHook, ForgeOutput, ForgeTool, HookKind};
use libextos::forge::forge::{Forge, ForgeConfig};
use libextos::forge::mkinitcpio::{self, MkinitcpioJob};
use libextos::forge::mount::{MountPlan, MountPlanOptions};

/// Environment variable carrying the boot root (`--boot-root` is the CLI form).
pub const ENV_BOOT_ROOT: &str = "EXTOS_BLS_ROOT";

/// Environment variable overriding the forge scratch directory.
pub const ENV_FORGE_SCRATCH: &str = "EXTOS_FORGE_SCRATCH";

/// Blueprint tool name the `mkinitcpio` bridge looks up first.
pub const GENERATOR_TOOL: &str = "mkinitcpio";

/// Cas object paths probed for the generator, in lookup order.
pub const GENERATOR_LOCATIONS: [&str; 4] = [
    "usr/bin/mkinitcpio",
    "bin/mkinitcpio",
    "usr/sbin/mkinitcpio",
    "sbin/mkinitcpio",
];

/// Hooks every derived blueprint starts with (all shipped by `mkinitcpio`).
pub const BASELINE_HOOKS: [&str; 5] = ["base", "udev", "modconf", "block", "filesystems"];

/// Artifact name used when `boot.initrd` is not declared.
pub const DEFAULT_ARTIFACT: &str = "initramfs-linux.img";

/// Kernel label used for BLS metadata when the config declares none.
pub const DEFAULT_KERNEL_LABEL: &str = "extos";

/// Maximum length of a token accepted as a hook name (blueprint grammar bound).
const MAX_HOOK_TOKEN_LEN: usize = 64;

/// One woven package: its `origin/name` label and the CAS object hash.
///
/// The forge needs only the object ids; taking labels too keeps the printed
/// derivation traceable to the package that provided the generator.
#[derive(Debug, Clone, Copy)]
pub struct PackageSource<'a> {
    /// `origin/name`, used in log lines.
    pub label: &'a str,
    /// CAS object hash holding the package payload.
    pub hash: &'a str,
}

/// Everything the derivation needs — all of it caller-supplied.
#[derive(Debug, Clone)]
pub struct ForgeRequest<'a> {
    /// Boot root: holds the artifact and `loader/{entries,loader.conf}`.
    pub boot_root: &'a Path,
    /// Scratch directory the forge tmpfs is staged under.
    pub scratch: &'a Path,
    /// Generation number the BLS ids carry.
    pub generation: u64,
    /// System name (BLS `title`/`sort-key`/id component).
    pub system: &'a str,
    /// Kernel version (`-k`, BLS `version`).
    pub kernel: Option<&'a str>,
    /// Early modules from `boot.modules` (see the module docs for the caveat).
    pub modules: &'a [String],
    /// Kernel command line (`boot.cmdline`).
    pub cmdline: Option<&'a str>,
    /// Declared initramfs path; its file name becomes the artifact name.
    pub initrd: Option<&'a Path>,
    /// Declared `linux = "…"` boot image; required to write BLS entries.
    pub linux: Option<&'a Path>,
    /// Woven packages, in declaration order.
    pub packages: &'a [PackageSource<'a>],
}

/// What the forge phase did (the typed outcome PLAN 4.2.6 asks for).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForgePhase {
    /// An initramfs was produced inside the forge.
    Forged {
        /// Harvested artifact (host path inside the boot root).
        artifact: PathBuf,
        /// Size in bytes (always non-zero).
        size: u64,
    },
    /// The forge could not run; `apply` continues and records why.
    Skipped {
        /// Operator-facing reason, printed verbatim.
        reason: String,
    },
}

impl ForgePhase {
    /// `forged` / `skipped` — the token recorded in the generation description.
    pub fn summary(&self) -> &'static str {
        match self {
            Self::Forged { .. } => "forged",
            Self::Skipped { .. } => "skipped",
        }
    }
}

impl std::fmt::Display for ForgePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Forged { artifact, size } => {
                write!(f, "forged {} ({size} bytes)", artifact.display())
            }
            Self::Skipped { reason } => write!(f, "skipped: {reason}"),
        }
    }
}

/// Result of the whole forge phase.
#[derive(Debug, Clone)]
pub struct ForgeReport {
    /// Typed outcome.
    pub phase: ForgePhase,
    /// BLS write report, when entries were written.
    pub bls: Option<BlsReport>,
}

impl ForgeReport {
    /// A report for a forge that never started.
    fn skipped(reason: impl Into<String>) -> Self {
        Self {
            phase: ForgePhase::Skipped {
                reason: reason.into(),
            },
            bls: None,
        }
    }

    /// Number of BLS entries written or already identical.
    pub fn bls_entries(&self) -> usize {
        self.bls.as_ref().map(BlsReport::total).unwrap_or(0)
    }
}

/// A blueprint successfully derived from the system config.
#[derive(Debug, Clone)]
struct Derivation {
    blueprint: ForgeBlueprint,
    text: String,
    artifact: String,
    kernel: String,
    notes: Vec<String>,
}

/// Outcome of the derivation step.
enum Derived {
    /// A validated blueprint, ready to build a mount plan from.
    Ready(Derivation),
    /// No blueprint can be derived; `apply` continues.
    Unavailable { reason: String, notes: Vec<String> },
}

/// Derive a forge blueprint from the system config (see the module docs).
///
/// Pure apart from reading CAS payloads: nothing is created, executed or
/// mutated, so a failure here is always reported before any forge side effect.
fn derive(repo: &CasRepository, request: &ForgeRequest<'_>) -> Derived {
    let mut notes = Vec::new();

    let Some((object, exec, provider)) = find_generator(repo, request.packages) else {
        return Derived::Unavailable {
            reason: format!(
                "no woven package ships an executable `{GENERATOR_TOOL}` (looked in {})",
                GENERATOR_LOCATIONS.join(", ")
            ),
            notes,
        };
    };

    let hooks = derive_hooks(request, &mut notes);
    let artifact = derive_artifact(request);
    let kernel = request.kernel.unwrap_or(DEFAULT_KERNEL_LABEL).to_string();

    let blueprint = ForgeBlueprint {
        tools: vec![ForgeTool {
            name: GENERATOR_TOOL.to_string(),
            object,
            exec: Some(exec.clone()),
        }],
        hooks,
        binds: Vec::new(),
        output: ForgeOutput {
            dir: request.boot_root.to_path_buf(),
            name: artifact.clone(),
            preset: None,
            kernel: Some(kernel.clone()),
        },
    };
    if let Err(error) = blueprint.validate() {
        return Derived::Unavailable {
            reason: format!("derived blueprint is invalid: {error}"),
            notes,
        };
    }

    let text = render_blueprint(&blueprint);
    notes.push(format!("generator: {provider} provides {}", exec.display()));
    Derived::Ready(Derivation {
        blueprint,
        text,
        artifact,
        kernel,
        notes,
    })
}

/// First woven package shipping an executable generator, in declaration order.
fn find_generator(
    repo: &CasRepository,
    packages: &[PackageSource<'_>],
) -> Option<(String, PathBuf, String)> {
    for package in packages {
        let content = repo.object_path(package.hash).join("content");
        for location in GENERATOR_LOCATIONS {
            let candidate = content.join(location);
            let is_executable = candidate
                .metadata()
                .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
                .unwrap_or(false);
            if is_executable {
                return Some((
                    package.hash.to_string(),
                    PathBuf::from(location),
                    package.label.to_string(),
                ));
            }
        }
    }
    None
}

/// Baseline hooks plus `boot.modules`, de-duplicated and order preserving.
fn derive_hooks(request: &ForgeRequest<'_>, notes: &mut Vec<String>) -> Vec<ForgeHook> {
    let mut names: Vec<String> = BASELINE_HOOKS.iter().map(|hook| hook.to_string()).collect();
    let mut module_tokens = 0usize;
    let mut rejected = Vec::new();
    for module in request.modules {
        let token = module.trim();
        let acceptable = !token.is_empty()
            && token.len() <= MAX_HOOK_TOKEN_LEN
            && token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+'));
        if !acceptable {
            rejected.push(module.clone());
            continue;
        }
        if names.iter().any(|existing| existing == token) {
            continue;
        }
        names.push(token.to_string());
        module_tokens += 1;
    }
    if module_tokens > 0 {
        notes.push(format!(
            "{module_tokens} `boot.modules` entr(ies) requested as hooks: the mkinitcpio bridge \
             renders MODULES=() today (see the instanz forge module docs)"
        ));
    }
    if !rejected.is_empty() {
        notes.push(format!(
            "boot.modules entr(ies) rejected as hook tokens (charset/length), ignored: {}",
            rejected.join(", ")
        ));
    }
    names
        .into_iter()
        .map(|name| ForgeHook {
            name,
            kind: HookKind::Install,
            object: None,
            path: None,
        })
        .collect()
}

/// Artifact file name: `boot.initrd`'s file name, else the default.
fn derive_artifact(request: &ForgeRequest<'_>) -> String {
    request
        .initrd
        .and_then(|path| path.file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| DEFAULT_ARTIFACT.to_string())
}

/// Render the derived blueprint as `.nix` text (printed, never re-parsed).
fn render_blueprint(blueprint: &ForgeBlueprint) -> String {
    let tools = blueprint
        .tools
        .iter()
        .map(|tool| {
            format!(
                "{{ name = \"{}\"; object = \"{}\"; exec = \"{}\"; }}",
                tool.name,
                tool.object,
                tool.exec
                    .as_ref()
                    .map(|exec| exec.display().to_string())
                    .unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    let hooks = blueprint
        .hooks
        .iter()
        .map(|hook| {
            format!(
                "{{ name = \"{}\"; kind = \"{}\"; }}",
                hook.name,
                hook.kind.as_str()
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "{{\n  tools = [ {tools} ];\n  hooks = [ {hooks} ];\n  output = {{ dir = \"{}\"; name = \"{}\"; kernel = \"{}\"; }};\n}}",
        blueprint.output.dir.display(),
        blueprint.output.name,
        blueprint.output.kernel.clone().unwrap_or_default()
    )
}

/// Run the forge phase for one apply (PLAN 4.2.6).
///
/// Returns a [`ForgeReport`] whose [`ForgePhase`] is `Forged` or `Skipped`.
/// Only *real* forge errors (invalid derivation, generator failure, artifact
/// missing, BLS collision) are returned as `Err`, and those are fatal to the
/// apply because they mean the blueprint or the system is wrong.
pub fn run_forge(repo: &CasRepository, request: &ForgeRequest<'_>) -> anyhow::Result<ForgeReport> {
    let derivation = match derive(repo, request) {
        Derived::Ready(derivation) => derivation,
        Derived::Unavailable { reason, notes } => {
            println!("        ⚠ forge skipped: {reason}");
            for note in &notes {
                println!("        · {note}");
            }
            return Ok(ForgeReport::skipped(reason));
        }
    };

    println!("        derived blueprint:");
    for line in derivation.text.lines() {
        println!("          {line}");
    }
    for note in &derivation.notes {
        println!("        · {note}");
    }

    fs::create_dir_all(request.boot_root).with_context(|| {
        format!(
            "cannot create the boot root {} (the forge binds it read-write)",
            request.boot_root.display()
        )
    })?;
    fs::create_dir_all(request.scratch).with_context(|| {
        format!(
            "cannot create the forge scratch directory {}",
            request.scratch.display()
        )
    })?;

    let mut plan = MountPlan::build_with(
        &derivation.blueprint,
        repo,
        request.scratch,
        &MountPlanOptions::from_env(),
    )
    .map_err(|error| forge_error(error, "cannot assemble the forge mount plan"))?;

    let job = MkinitcpioJob::from_blueprint(&derivation.blueprint, &plan);
    if plan.tool_program(GENERATOR_TOOL).is_none() && mkinitcpio::probe(&job.binary).is_none() {
        let reason = format!(
            "generator `{}` is not resolvable inside the forge (ship it in a package, put it on \
             PATH under a bound runtime dir, or set EXTOS_MKINITCPIO for a custom blueprint)",
            job.binary
        );
        println!("        ⚠ forge skipped: {reason}");
        return Ok(ForgeReport::skipped(reason));
    }

    mkinitcpio::stage_config(&mut plan, &job)
        .map_err(|error| forge_error(error, "cannot stage mkinitcpio.conf in the forge"))?;

    let forge = Forge::new(plan, ForgeConfig::from_env());
    let outcome = match mkinitcpio::run(&forge, &job) {
        Ok(outcome) => outcome,
        Err(ForgeError::NamespaceUnavailable { message }) => {
            let reason = format!("mount namespace unavailable on this host: {message}");
            println!("        ⚠ forge skipped: {reason}");
            return Ok(ForgeReport::skipped(reason));
        }
        Err(error) => return Err(forge_error(error, "runlevel-0 forge failed")),
    };

    println!(
        "        ✓ forged {} ({} bytes, generator {})",
        outcome.artifact.display(),
        outcome.artifact_size,
        job.binary
    );

    let bls = write_bls_entries(request, &derivation)?;
    if bls.is_none() {
        println!(
            "        · BLS entries skipped: the config declares no `linux = \"…\"` boot image path"
        );
    }

    Ok(ForgeReport {
        phase: ForgePhase::Forged {
            artifact: outcome.artifact,
            size: outcome.artifact_size,
        },
        bls,
    })
}

/// Publish the BLS matrix for this generation (PLAN 4.2.4/4.2.5).
///
/// `loader.conf` uses the bridge's `CreateIfMissing` policy: a fresh boot root
/// gets a `default <newest>` line, an existing file is *never* rewritten, so a
/// user edit survives an apply. That is the Phase-2 residual closed at apply
/// time, and the action is printed either way.
fn write_bls_entries(
    request: &ForgeRequest<'_>,
    derivation: &Derivation,
) -> anyhow::Result<Option<BlsReport>> {
    let Some(linux) = request.linux else {
        return Ok(None);
    };

    let kernel = BootKernel {
        kernel: derivation.kernel.clone(),
        linux: linux.to_path_buf(),
        initrd: vec![PathBuf::from(format!("/{}", derivation.artifact))],
        options: request.cmdline.map(str::to_string),
    };
    let systems = [BlsSystem {
        system: request.system.to_string(),
        generation: request.generation,
        kernels: vec![kernel],
    }];
    let plan = BlsPlan::from_systems(
        &systems,
        &BlsPlanOptions {
            extra_options: None,
            ..BlsPlanOptions::default()
        },
    )
    .map_err(|error| forge_error(error, "cannot build the BLS entry matrix"))?;

    let report = plan
        .write(request.boot_root, &BlsWriteOptions::create_if_missing())
        .map_err(|error| forge_error(error, "cannot write BLS entries"))?;

    for path in &report.written {
        println!("        ✓ BLS entry {}", path.display());
    }
    for path in &report.unchanged {
        println!("        · BLS entry {} already current", path.display());
    }
    match &report.loader_conf {
        LoaderConfAction::Created(path) => println!(
            "        ✓ loader.conf created {} (default {})",
            path.display(),
            report.default.as_deref().unwrap_or("<none>")
        ),
        LoaderConfAction::Preserved {
            path,
            current_default,
        } => println!(
            "        · loader.conf preserved {} (existing default {}; user edits kept)",
            path.display(),
            current_default.as_deref().unwrap_or("<unset>")
        ),
        LoaderConfAction::Disabled => {
            println!("        · loader.conf untouched (policy disabled or no entries)")
        }
    }
    Ok(Some(report))
}

/// Wrap a [`ForgeError`] with the phase that failed (keeps the source chain).
fn forge_error(error: ForgeError, context: &str) -> anyhow::Error {
    anyhow::Error::new(error).context(context.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use libextos::types::HashAlgorithm;

    fn repo_with(dir: &Path, files: &[(&str, &str, u32)]) -> (CasRepository, String) {
        let repo = CasRepository::open(dir.join("repo"), HashAlgorithm::Blake3).unwrap();
        let payload = dir.join("payload");
        for (rel, contents, mode) in files {
            let path = payload.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, contents).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(*mode)).unwrap();
        }
        let hash = repo.store_directory(&payload).unwrap();
        (repo, hash)
    }

    fn request<'a>(
        boot_root: &'a Path,
        scratch: &'a Path,
        packages: &'a [PackageSource<'a>],
        modules: &'a [String],
    ) -> ForgeRequest<'a> {
        ForgeRequest {
            boot_root,
            scratch,
            generation: 4,
            system: "fixture",
            kernel: Some("6.11.0-extos"),
            modules,
            cmdline: Some("quiet"),
            initrd: Some(Path::new("/boot/initramfs-extos.img")),
            linux: Some(Path::new("/vmlinuz")),
            packages,
        }
    }

    #[test]
    fn derivation_names_the_in_cas_generator_and_the_caller_boot_root() {
        let tmp = tempfile::tempdir().unwrap();
        let (repo, hash) = repo_with(
            tmp.path(),
            &[("usr/bin/mkinitcpio", "#!/bin/sh\nexit 0\n", 0o755)],
        );
        let packages = [PackageSource {
            label: "archlinux/mkinitcpio",
            hash: &hash,
        }];
        let modules = vec!["ext4".to_string(), "btrfs".to_string()];
        let boot = tmp.path().join("boot");
        let scratch = tmp.path().join("scratch");
        let request = request(&boot, &scratch, &packages, &modules);

        let Derived::Ready(derivation) = derive(&repo, &request) else {
            panic!("derivation must succeed");
        };
        assert_eq!(derivation.blueprint.tools.len(), 1);
        assert_eq!(derivation.blueprint.tools[0].name, GENERATOR_TOOL);
        assert_eq!(derivation.blueprint.tools[0].object, hash);
        assert_eq!(
            derivation.blueprint.tools[0].exec.as_deref(),
            Some(Path::new("usr/bin/mkinitcpio"))
        );
        // Baseline hooks, then the modules, in order.
        let hooks = derivation.blueprint.hook_names();
        assert_eq!(&hooks[..BASELINE_HOOKS.len()], &BASELINE_HOOKS);
        assert_eq!(&hooks[BASELINE_HOOKS.len()..], &["ext4", "btrfs"]);
        // `boot.initrd`'s file name is the artifact; `boot.kernel` the label.
        assert_eq!(derivation.artifact, "initramfs-extos.img");
        assert_eq!(derivation.kernel, "6.11.0-extos");
        // The boot root is the caller's, never a built-in `/boot`.
        assert_eq!(derivation.blueprint.output.dir, boot);
        assert!(derivation.text.contains("hooks = [ { name = \"base\""));
        assert!(
            derivation
                .notes
                .iter()
                .any(|note| note.contains("MODULES=()"))
        );
    }

    #[test]
    fn derivation_skips_with_a_reason_when_no_package_ships_the_generator() {
        let tmp = tempfile::tempdir().unwrap();
        let (repo, hash) = repo_with(tmp.path(), &[("usr/bin/other", "#!/bin/sh\n", 0o755)]);
        let packages = [PackageSource {
            label: "archlinux/base",
            hash: &hash,
        }];
        let boot = tmp.path().join("boot");
        let scratch = tmp.path().join("scratch");
        let request = request(&boot, &scratch, &packages, &[]);

        match derive(&repo, &request) {
            Derived::Unavailable { reason, .. } => {
                assert!(reason.contains("no woven package ships"), "{reason}");
                assert!(reason.contains(GENERATOR_LOCATIONS[0]), "{reason}");
            }
            Derived::Ready(_) => panic!("expected an unavailable derivation"),
        }
        // Nothing was created by the failed derivation.
        assert!(!boot.exists());
    }

    #[test]
    fn non_executable_generator_is_not_picked_up() {
        let tmp = tempfile::tempdir().unwrap();
        let (repo, hash) = repo_with(
            tmp.path(),
            &[("usr/bin/mkinitcpio", "#!/bin/sh\nexit 0\n", 0o644)],
        );
        let packages = [PackageSource {
            label: "archlinux/mkinitcpio",
            hash: &hash,
        }];
        let boot = tmp.path().join("boot");
        let scratch = tmp.path().join("scratch");
        match derive(&repo, &request(&boot, &scratch, &packages, &[])) {
            Derived::Unavailable { reason, .. } => assert!(reason.contains("executable")),
            Derived::Ready(_) => panic!("0o644 payload must not be used as a generator"),
        }
    }

    #[test]
    fn hooks_are_deduplicated_and_invalid_tokens_are_dropped() {
        let tmp = tempfile::tempdir().unwrap();
        let (repo, hash) = repo_with(
            tmp.path(),
            &[("usr/sbin/mkinitcpio", "#!/bin/sh\nexit 0\n", 0o755)],
        );
        let packages = [PackageSource {
            label: "archlinux/mkinitcpio",
            hash: &hash,
        }];
        let modules = vec![
            "udev".to_string(), // already a baseline hook
            "ext4".to_string(),
            "bad hook".to_string(), // space → not a hook token
            String::new(),          // empty
            "overlay".to_string(),
        ];
        let boot = tmp.path().join("boot");
        let scratch = tmp.path().join("scratch");
        let Derived::Ready(derivation) =
            derive(&repo, &request(&boot, &scratch, &packages, &modules))
        else {
            panic!("derivation must succeed");
        };
        let hooks = derivation.blueprint.hook_names();
        assert_eq!(hooks.iter().filter(|hook| **hook == "udev").count(), 1);
        assert!(hooks.contains(&"ext4"));
        assert!(hooks.contains(&"overlay"));
        assert!(!hooks.contains(&"bad hook"));
        assert_eq!(hooks.last().copied(), Some("overlay"));
        assert!(
            derivation
                .notes
                .iter()
                .any(|note| note.contains("rejected as hook tokens")),
            "{:?}",
            derivation.notes
        );
    }

    #[test]
    fn artifact_defaults_when_boot_initrd_is_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let (repo, hash) = repo_with(
            tmp.path(),
            &[("bin/mkinitcpio", "#!/bin/sh\nexit 0\n", 0o755)],
        );
        let packages = [PackageSource {
            label: "archlinux/mkinitcpio",
            hash: &hash,
        }];
        let boot = tmp.path().join("boot");
        let scratch = tmp.path().join("scratch");
        let mut request = request(&boot, &scratch, &packages, &[]);
        request.initrd = None;
        request.kernel = None;
        let Derived::Ready(derivation) = derive(&repo, &request) else {
            panic!("derivation must succeed");
        };
        assert_eq!(derivation.artifact, DEFAULT_ARTIFACT);
        assert_eq!(derivation.kernel, DEFAULT_KERNEL_LABEL);
    }

    #[test]
    fn phase_summary_is_the_token_recorded_in_the_generation() {
        let forged = ForgePhase::Forged {
            artifact: PathBuf::from("/boot/initramfs-linux.img"),
            size: 42,
        };
        assert_eq!(forged.summary(), "forged");
        assert!(forged.to_string().contains("42 bytes"));

        let skipped = ForgePhase::Skipped {
            reason: "no mkinitcpio".into(),
        };
        assert_eq!(skipped.summary(), "skipped");
        assert!(skipped.to_string().contains("no mkinitcpio"));
    }
}
