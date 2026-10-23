//! `instanz run <profile>` — boot a container from an applied roof (PLAN 4.4.8).
//!
//! This is the CLI half of the container runtime: `libextos::container` already
//! owns spec assembly, rootfs layout, namespaces, PTYs, backend probing and the
//! launch itself. What lives here is the *decision* layer the CLI needs:
//!
//! 1. **Which tree?** `run` never weaves. It resolves `<rootfs>/current` to the
//!    applied generation directory and refuses to invent a rootfs, so
//!    `instanz run` on a system that was never applied is a typed error rather
//!    than a confusing container failure.
//! 2. **Which profile?** The positional argument names a *system* or a package
//!    profile. If a system config is available, the named package's manifest is
//!    consulted for `containerPermissions` (level, sockets, entrypoint). A
//!    profile is a *request*: levels/backends are re-checked by the launcher
//!    against the selected backend, and level 4 still needs `--allow-privileged`.
//! 3. **Which backend?** `--backend` wins, else `EXTOS_CONTAINER_BACKEND`, else
//!    the native backend. The host probe is printed so an unsupported
//!    combination is explained before it is attempted.
//! 4. **Exit status.** The container's exit code is propagated to `instanz`
//!    (signals become `128 + signal`), so `instanz run … ; echo $?` is honest.
//!
//! # Honest limits
//!
//! * Output is **replayed, not streamed**: `LaunchOutcome::output` is returned
//!   once the payload exits (`libextos` reads the PTY to EOF), so an interactive
//!   session shows its screen after it ends. Level-1 PTY allocation, window size
//!   and CR/LF handling are the library's; live forwarding needs an incremental
//!   reader that the current `container::pty` API does not expose.
//! * Only the *applied generation* rootfs is used. Staging a lower-level rootfs
//!   from a subset plan (`container::assemble_rootfs`) stays a library
//!   capability; the CLI does not re-weave packages for `run`.
//! * The generation is handed to the launcher as a **directory projection**
//!   ([`RoofProjection`]): a temporary directory whose top-level entries are
//!   symlinks to the generation's directories. The launcher's tmpfs-root
//!   strategy binds every top-level entry and cannot bind the generation's
//!   metadata file `.lock` (a bind mount of a file onto a directory fails), and
//!   a `chroot`-only root would make the woven tree writable. The projection
//!   keeps the read-only tmpfs root and the CAS hardlinks protected; top-level
//!   *files* are not container payload and are reported when skipped.

use std::fs;
use std::io::Write as _;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, anyhow, bail};
use libextos::cas::CasRepository;
use libextos::container::{
    Backend, BackendProbe, ContainerPermissions, IsolationLevel, LaunchSpec, RootMode, launch,
};
use libextos::manifest::PackageManifest;

use crate::orchestrate::load_manifest;
use crate::system::SystemConfig;

/// Environment variable naming the system config used for profile lookup.
pub const ENV_SYSTEM_CONFIG: &str = "EXTOS_SYSTEM_CONFIG";

/// One `instanz run` invocation, already parsed by clap.
#[derive(Debug, Clone)]
pub struct RunOptions<'a> {
    /// Generations root (`--rootfs` / `EXTOS_ROOTFS`).
    pub rootfs: &'a Path,
    /// System name or package profile name.
    pub profile: &'a str,
    /// `--level 0..4`; overrides the manifest profile when set.
    pub level: Option<u8>,
    /// `--backend native|nspawn|runc|crun|chroot`.
    pub backend: Option<&'a str>,
    /// Explicit in-container program (overrides the profile entrypoint).
    pub program: Option<&'a str>,
    /// Extra arguments appended to the program.
    pub args: &'a [String],
    /// System config used for `containerPermissions` lookup, if any.
    pub config: Option<&'a Path>,
    /// Explicit opt-in for a level-4 (privileged) launch.
    pub allow_privileged: bool,
}

/// Run one container and return the exit code to propagate.
pub fn run(repo: Option<&CasRepository>, options: &RunOptions<'_>) -> anyhow::Result<i32> {
    let roof = resolve_roof(options.rootfs)?;
    let projection = RoofProjection::create(&roof)
        .with_context(|| format!("cannot project the generation at {}", roof.display()))?;

    let (profile, profile_note) = resolve_profile(repo, options)?;
    let level = match options.level {
        Some(level) => IsolationLevel::from_u8(level).ok_or_else(|| {
            anyhow!("invalid isolation level {level}: expected 0 (isolated) … 4 (privileged)")
        })?,
        None => profile
            .as_ref()
            .map(|profile| profile.level)
            .unwrap_or(IsolationLevel::Isolated),
    };

    // A level override replaces the level-derived policy (sockets, namespace
    // toggles) but keeps the profile's entrypoint: mixing a level-1 namespace
    // set with a level-4 request would request facilities the operator did not
    // ask for (and `RuntimePolicy::validate` would refuse it).
    let effective = effective_permissions(profile.as_ref(), level);

    let program = options
        .program
        .map(str::to_string)
        .or_else(|| effective.command.first().cloned())
        .ok_or_else(|| {
            anyhow!(
                "no container program: pass `--program <path inside the roof>` or declare \
                 `containerPermissions.command` in the package manifest (profile {:?})",
                options.profile
            )
        })?;
    let args = program_args(options, &effective, options.program.is_none());

    let backend = resolve_backend(options.backend)?;
    let probe = BackendProbe::discover();

    println!("roof      : {}", roof.display());
    println!(
        "stage     : {} (read-only tmpfs root)",
        projection.path().display()
    );
    if !projection.skipped.is_empty() {
        println!(
            "note      : generation metadata not mounted into the container: {}",
            projection.skipped.join(", ")
        );
    }
    println!("profile   : {} — {}", options.profile, profile_note);
    println!("level     : {} ({})", level.as_u8(), level.as_str());
    println!(
        "program   : {}{}",
        program,
        if args.is_empty() {
            String::new()
        } else {
            format!(" {}", args.join(" "))
        }
    );
    println!("backend   : {}", backend.as_str());
    if let Some(binary) = backend.binary() {
        println!("backend bin: {binary}");
    }
    for line in probe.report().lines() {
        println!("probe     : {line}");
    }
    if level == IsolationLevel::Privileged && !options.allow_privileged {
        println!(
            "note      : level 4 needs `--allow-privileged`; the launcher will refuse otherwise"
        );
    }

    let mut spec = LaunchSpec::from_profile(&effective, projection.path(), Some(&program));
    spec.level = level;
    spec.args = args;
    spec.backend = backend;
    spec.allow_privileged = options.allow_privileged;
    // The library default (`TmpfsBind`) is exactly what the projection enables;
    // spell it out so a future default change cannot silently chroot the tree.
    spec.root_mode = RootMode::TmpfsBind;

    let outcome = launch(&spec)
        .map_err(|error| anyhow!("container launch failed: {error}"))
        .with_context(|| format!("profile {:?} at level {level}", options.profile))?;

    for warning in &outcome.warnings {
        println!("warning   : {warning}");
    }
    let mut stdout = std::io::stdout();
    stdout
        .write_all(&outcome.output)
        .context("cannot write the container output")?;
    stdout.flush().ok();

    let code = outcome
        .status
        .code()
        .unwrap_or_else(|| 128 + outcome.status.signal().unwrap_or(0));
    println!(
        "exit      : {code} ({}, pty {})",
        outcome.backend.as_str(),
        if outcome.pty { "yes" } else { "no" }
    );
    Ok(code)
}

/// Effective profile after applying a `--level` override.
///
/// The declared level wins when it matches; otherwise the level-derived
/// sockets/namespaces are rebuilt for the requested level and the declared
/// program (plus its args) is kept, so `--level` changes isolation, not intent.
fn effective_permissions(
    profile: Option<&ContainerPermissions>,
    level: IsolationLevel,
) -> ContainerPermissions {
    match profile {
        Some(declared) if declared.level == level => declared.clone(),
        Some(declared) => {
            let defaults = ContainerPermissions::new(level);
            ContainerPermissions {
                level,
                sockets: defaults.sockets,
                namespaces: defaults.namespaces,
                command: declared.command.clone(),
            }
        }
        None => ContainerPermissions::new(level),
    }
}

/// `<rootfs>/current` → generation directory; typed error when not applied.
fn resolve_roof(rootfs: &Path) -> anyhow::Result<PathBuf> {
    let link = rootfs.join("current");
    let target = match fs::read_link(&link) {
        Ok(target) => target,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            bail!(
                "run requires an applied system: {} has no `current` generation \
                 (run `instanz apply` first, or pass --rootfs/EXTOS_ROOTFS)",
                rootfs.display()
            )
        }
        Err(error) => {
            return Err(anyhow::Error::new(error)
                .context(format!("cannot read the `current` link {}", link.display())));
        }
    };
    let roof = if target.is_absolute() {
        target
    } else {
        rootfs.join(target)
    };
    if !roof.is_dir() {
        bail!(
            "run requires an applied system: `current` points at {} which is not a directory",
            roof.display()
        )
    }
    Ok(roof)
}

/// A temporary directory whose top-level entries link to the generation's
/// directories, so the launcher's tmpfs-root strategy can bind every entry.
///
/// The applied generation also holds `.lock` (a regular file) and possibly a
/// stale `.extos-root` mountpoint from an earlier launch. Binding a file onto a
/// directory target fails, and binding `.extos-root` onto itself is pointless,
/// so both are left out; [`RoofProjection::skipped`] reports the files.
///
/// Removing the directory never follows the symlinks (Rust's `remove_dir_all`
/// unlinks them), so the generation and the CAS behind the roof stay untouched.
struct RoofProjection {
    dir: PathBuf,
    skipped: Vec<String>,
}

impl RoofProjection {
    /// Top-level directories the container mount table needs as mountpoints.
    ///
    /// `container::mounts` mounts tmpfs at `/dev`, `/tmp`, `/run` and procfs at
    /// `/proc` *before* it creates parents, and binds `/etc/resolv.conf` for
    /// networked levels. A woven FHS generation normally has these, but a
    /// minimal fixture (or a level-0 roof) may not, so the projection supplies
    /// empty mountpoints. They carry no payload: real generation directories win.
    const MOUNTPOINTS: [&'static str; 5] = ["dev", "etc", "proc", "run", "tmp"];

    fn create(roof: &Path) -> anyhow::Result<Self> {
        let dir = std::env::temp_dir().join(format!(
            "extos-run-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        fs::create_dir_all(&dir)
            .with_context(|| format!("cannot create the run projection {}", dir.display()))?;
        let built = (|| -> anyhow::Result<Vec<String>> {
            let mut skipped = Vec::new();
            for entry in fs::read_dir(roof)? {
                let entry = entry?;
                let name = entry.file_name();
                let Some(name_text) = name.to_str() else {
                    skipped.push(name.to_string_lossy().into_owned());
                    continue;
                };
                if name_text == libextos::container::namespace::TMPFS_ROOT_DIR {
                    continue;
                }
                let source = entry.path();
                // `metadata` follows a packaged symlink: a link to a directory
                // is projected as a link, a link to a file is generation data.
                if fs::metadata(&source)?.is_dir() {
                    std::os::unix::fs::symlink(&source, dir.join(&name))
                        .with_context(|| format!("cannot project {}", source.display()))?;
                } else {
                    skipped.push(name_text.to_string());
                }
            }
            for mountpoint in Self::MOUNTPOINTS {
                let target = dir.join(mountpoint);
                if !target.exists() {
                    fs::create_dir(&target)
                        .with_context(|| format!("cannot create {}", target.display()))?;
                }
            }
            skipped.sort();
            Ok(skipped)
        })();
        match built {
            Ok(skipped) => Ok(Self { dir, skipped }),
            Err(error) => {
                let _ = fs::remove_dir_all(&dir);
                Err(error)
            }
        }
    }

    /// Directory to hand the launcher.
    fn path(&self) -> &Path {
        &self.dir
    }
}

impl Drop for RoofProjection {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Monotonic-ish suffix for per-launch temporary directories.
fn unique_suffix() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

/// Resolve `--backend` / `EXTOS_CONTAINER_BACKEND` / native.
fn resolve_backend(flag: Option<&str>) -> anyhow::Result<Backend> {
    match flag {
        Some(name) => Backend::from_name(name.trim()).map_err(|error| anyhow!("{error}")),
        None => Backend::from_env().map_err(|error| anyhow!("{error}")),
    }
}

/// Program arguments: the profile's tail plus the CLI tail.
///
/// `profile_owns_program` is false when `--program` replaced the entrypoint, in
/// which case the profile's arguments no longer belong to it.
fn program_args(
    options: &RunOptions<'_>,
    profile: &ContainerPermissions,
    profile_owns_program: bool,
) -> Vec<String> {
    let mut args = if profile_owns_program {
        profile.command.get(1..).unwrap_or(&[]).to_vec()
    } else {
        Vec::new()
    };
    args.extend(options.args.iter().cloned());
    args
}

/// Look up a manifest-declared `containerPermissions` profile.
///
/// Returns `(profile, note)`. Every "no profile" outcome is a *printed note*
/// plus `None`, never an error: a system name without a containerised package is
/// a legitimate invocation when `--program` and `--level` are given.
fn resolve_profile(
    repo: Option<&CasRepository>,
    options: &RunOptions<'_>,
) -> anyhow::Result<(Option<ContainerPermissions>, String)> {
    let Some(config_path) = system_config_path(options.config) else {
        return Ok((
            None,
            format!(
                "no system config found ({} or --config); using flags only",
                crate::system::DEFAULT_CONFIG_PATH
            ),
        ));
    };
    let Some(repo) = repo else {
        return Ok((
            None,
            format!(
                "system config {} not consulted: no CAS repository available",
                config_path.display()
            ),
        ));
    };

    let system = SystemConfig::load(&config_path)?;
    let expansion = system.expand(repo)?;

    // A profile name may be a system name (no manifest profile) or a package.
    let matched = expansion.refs.iter().find(|reference| {
        reference.name == options.profile
            || reference.label() == options.profile
            || format!("{}/{}", reference.origin, reference.name) == options.profile
    });
    let Some(reference) = matched else {
        return Ok((
            None,
            format!(
                "`{}` is not a package of {} ({} declared ref(s)); using flags only",
                options.profile,
                config_path.display(),
                expansion.refs.len()
            ),
        ));
    };

    let hash = repo.resolve_ref(&reference.origin, &reference.name, &reference.version)?;
    let manifest: PackageManifest = load_manifest(repo, &hash)?;
    match manifest.container {
        Some(profile) => {
            let note = format!(
                "manifest profile of {}: level {} ({}){}",
                reference.label(),
                profile.level.as_u8(),
                profile.level.as_str(),
                if profile.command.is_empty() {
                    String::new()
                } else {
                    format!(", command {}", profile.command.join(" "))
                }
            );
            Ok((Some(profile), note))
        }
        None => Ok((
            None,
            format!(
                "{} declares no `containerPermissions`; using flags only",
                reference.label()
            ),
        )),
    }
}

/// Explicit `--config`, else the documented default when it exists.
fn system_config_path(flag: Option<&Path>) -> Option<PathBuf> {
    match flag {
        Some(path) => Some(path.to_path_buf()),
        None => {
            let default = PathBuf::from(crate::system::DEFAULT_CONFIG_PATH);
            default.is_file().then_some(default)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::DEFAULT_CONFIG_PATH;

    #[test]
    fn missing_current_generation_is_a_typed_error() {
        let tmp = tempfile::tempdir().unwrap();
        let error = resolve_roof(tmp.path()).unwrap_err().to_string();
        assert!(error.contains("run requires an applied system"), "{error}");
        assert!(error.contains("instanz apply"), "{error}");
    }

    #[test]
    fn dangling_current_is_a_typed_error() {
        let tmp = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("gen-9", tmp.path().join("current")).unwrap();
        let error = resolve_roof(tmp.path()).unwrap_err().to_string();
        assert!(error.contains("not a directory"), "{error}");
    }

    #[test]
    fn current_resolves_to_the_generation_directory() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("gen-3/usr")).unwrap();
        std::os::unix::fs::symlink("gen-3", tmp.path().join("current")).unwrap();
        let roof = resolve_roof(tmp.path()).unwrap();
        assert_eq!(roof, tmp.path().join("gen-3"));
        assert!(roof.join("usr").is_dir());
    }

    #[test]
    fn roof_projection_exposes_directories_and_skips_generation_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let generation = tmp.path().join("gen-1");
        fs::create_dir_all(generation.join("usr/bin")).unwrap();
        fs::write(generation.join(".lock"), "lockfile\n").unwrap();
        fs::create_dir_all(generation.join(".extos-root")).unwrap();

        let projection = RoofProjection::create(&generation).unwrap();
        assert!(projection.path().join("usr").is_dir());
        assert!(projection.path().join("usr/bin").is_dir());
        // The lockfile cannot be bind-mounted as a root entry; the stale
        // mountpoint must not be bound onto itself.
        assert!(!projection.path().join(".lock").exists());
        assert!(!projection.path().join(".extos-root").exists());
        assert_eq!(projection.skipped, vec![".lock".to_string()]);

        // Dropping the projection removes only the links, never the generation.
        let stage = projection.path().to_path_buf();
        drop(projection);
        assert!(!stage.exists());
        assert!(generation.join(".lock").is_file());
        assert!(generation.join("usr/bin").is_dir());
    }

    #[test]
    fn backend_flag_accepts_names_and_rejects_unknown_ones() {
        assert_eq!(resolve_backend(Some("native")).unwrap(), Backend::Native);
        let error = resolve_backend(Some("definitely-not-a-backend"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown container backend"), "{error}");
    }

    #[test]
    fn level_override_keeps_the_profile_command_but_not_its_namespaces() {
        let declared = ContainerPermissions::new(IsolationLevel::Cli)
            .with_command(["/usr/bin/app".to_string(), "--flag".to_string()]);

        // Same level: the declared profile is used verbatim.
        let same = effective_permissions(Some(&declared), IsolationLevel::Cli);
        assert_eq!(same.level, IsolationLevel::Cli);
        assert_eq!(same.command, declared.command);

        // Override: intent (command) survives, isolation policy is rebuilt.
        let isolated = effective_permissions(Some(&declared), IsolationLevel::Isolated);
        assert_eq!(isolated.level, IsolationLevel::Isolated);
        assert_eq!(isolated.command, declared.command);
        assert_eq!(
            isolated.namespaces,
            ContainerPermissions::new(IsolationLevel::Isolated).namespaces
        );
        assert!(
            isolated.sockets.is_empty(),
            "level 0 has no display sockets"
        );

        // No profile at all: defaults for the level.
        let bare = effective_permissions(None, IsolationLevel::Gui);
        assert_eq!(bare.level, IsolationLevel::Gui);
        assert!(bare.command.is_empty());
        assert!(!bare.sockets.is_empty(), "level 2 declares display sockets");
    }

    #[test]
    fn profile_arguments_are_dropped_when_program_is_overridden() {
        let profile = ContainerPermissions::new(IsolationLevel::Cli)
            .with_command(["/usr/bin/app".to_string(), "--flag".to_string()]);
        let rootfs = Path::new("/tmp/rootfs");
        let extra = vec!["--extra".to_string()];

        let derived = RunOptions {
            rootfs,
            profile: "app",
            level: None,
            backend: None,
            program: None,
            args: &extra,
            config: None,
            allow_privileged: false,
        };
        assert_eq!(
            program_args(&derived, &profile, true),
            vec!["--flag", "--extra"]
        );

        let overridden = RunOptions {
            program: Some("/bin/sh"),
            ..derived.clone()
        };
        assert_eq!(program_args(&overridden, &profile, false), vec!["--extra"]);
    }

    #[test]
    fn system_config_path_prefers_the_flag() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("custom.nix");
        fs::write(&file, "{}").unwrap();
        assert_eq!(system_config_path(Some(&file)), Some(file));
        // The compile-time default path does not exist on a dev host.
        if !Path::new(DEFAULT_CONFIG_PATH).is_file() {
            assert_eq!(system_config_path(None), None);
        }
    }
}
