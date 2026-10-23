//! `/var` and `/home` bind-mount setup for a woven roof (PLAN task 4.1.5).
//!
//! Weaving materializes the *read-only* FHS tree of a generation; the mutable
//! parts of a runlevel-1 system come from bind mounts:
//!
//! * `/runlevel/1/<system>/var` — a host directory (or a tmpfs when the roof is
//!   declared ephemeral);
//! * `/runlevel/1/<system>/home` — the host's universal pool (ARCHITECTURE §13,
//!   conventionally `/user`, passed by the caller), so user data survives
//!   generation switches.
//!
//! # Honesty contract
//!
//! Creating a mount requires `CAP_SYS_ADMIN`. This module therefore separates
//! three steps:
//!
//! 1. [`plan_mounts`] — pure spec assembly, always available, fully testable;
//! 2. [`probe_mount_capability`] — a side-effect-free probe of the *current*
//!    process's effective capabilities (`/proc/self/status` `CapEff`);
//! 3. [`apply_mounts`] — runs the specs through a [`MountRunner`], but **only**
//!    when the probe says the process may mount. Otherwise every spec is
//!    reported as skipped with the reason, never silently treated as applied.
//!
//! The [`MountRunner`] indirection keeps the real syscall path out of tests:
//! [`HostMountRunner`] shells out to `mount(8)`, while tests inject a recorder.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// `CAP_SYS_ADMIN` bit in the kernel capability mask (bit 21).
const CAP_SYS_ADMIN_BIT: u32 = 21;

/// What kind of mount a spec describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountKind {
    /// Bind a host directory into the roof.
    Bind,
    /// Mount a fresh tmpfs (ephemeral mutable state).
    Tmpfs,
}

impl MountKind {
    /// Lowercase spelling used in logs.
    pub fn as_str(self) -> &'static str {
        match self {
            MountKind::Bind => "bind",
            MountKind::Tmpfs => "tmpfs",
        }
    }
}

/// One planned mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountSpec {
    /// Mount kind.
    pub kind: MountKind,
    /// Source path (for [`MountKind::Tmpfs`] this is the pseudo-source `tmpfs`).
    pub source: PathBuf,
    /// Absolute target inside the roof.
    pub target: PathBuf,
    /// `mount -o` options, already rendered (`rw`, `mode=0755`, …).
    pub options: Vec<String>,
}

impl MountSpec {
    /// Bind `source` onto `target`.
    pub fn bind(source: impl Into<PathBuf>, target: impl Into<PathBuf>) -> Self {
        Self {
            kind: MountKind::Bind,
            source: source.into(),
            target: target.into(),
            options: vec!["rw".to_string()],
        }
    }

    /// Mount a tmpfs at `target`.
    pub fn tmpfs(target: impl Into<PathBuf>, mode: &str) -> Self {
        Self {
            kind: MountKind::Tmpfs,
            source: PathBuf::from("tmpfs"),
            target: target.into(),
            options: vec![format!("mode={mode}")],
        }
    }

    /// `mount(8)` argv for this spec (program excluded).
    pub fn command_argv(&self) -> Vec<String> {
        let options = self.options.join(",");
        match self.kind {
            MountKind::Bind => vec![
                "--bind".to_string(),
                self.source.display().to_string(),
                self.target.display().to_string(),
            ],
            MountKind::Tmpfs => vec![
                "-t".to_string(),
                "tmpfs".to_string(),
                "-o".to_string(),
                options,
                "tmpfs".to_string(),
                self.target.display().to_string(),
            ],
        }
    }

    /// One-line rendering for logs (`bind /a -> /b`).
    pub fn label(&self) -> String {
        format!(
            "{} {} -> {}",
            self.kind.as_str(),
            self.source.display(),
            self.target.display()
        )
    }
}

/// Where the mutable directories of a roof come from.
#[derive(Debug, Clone, Default)]
pub struct MountSources {
    /// Host directory to bind onto `<roof>/var`; `None` falls back to tmpfs
    /// when [`MountSources::var_tmpfs`] is set.
    pub var: Option<PathBuf>,
    /// Host directory to bind onto `<roof>/home`.
    pub home: Option<PathBuf>,
    /// Mount `<roof>/var` as a tmpfs (only consulted when `var` is `None`).
    pub var_tmpfs: bool,
}

impl MountSources {
    /// Build a source set from the three config values (PLAN 4.1.5).
    pub fn new(
        var: Option<PathBuf>,
        home: Option<PathBuf>,
        var_tmpfs: bool,
    ) -> Self {
        Self {
            var,
            home,
            var_tmpfs,
        }
    }
}

/// Assemble the mount spec list for a roof root (PLAN 4.1.5).
///
/// Pure: no directory is created and nothing is mounted. Targets are the
/// roof's `var` and `home` children; a declared source contributes one spec, so
/// an empty [`MountSources`] yields an empty list (the roof keeps the woven,
/// generation-local directories).
pub fn plan_mounts(root: &Path, sources: &MountSources) -> Vec<MountSpec> {
    let mut specs = Vec::new();
    match &sources.var {
        Some(source) => specs.push(MountSpec::bind(source.clone(), root.join("var"))),
        None if sources.var_tmpfs => specs.push(MountSpec::tmpfs(root.join("var"), "0755")),
        None => {}
    }
    if let Some(source) = &sources.home {
        specs.push(MountSpec::bind(source.clone(), root.join("home")));
    }
    specs
}

// ─── Capability probe ───────────────────────────────────────────

/// Whether the current process may create mounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountCapability {
    /// The process holds `CAP_SYS_ADMIN`: real mounts may be attempted.
    Available,
    /// Real mounts are impossible here; carries the operator-facing reason.
    Unavailable(String),
}

impl MountCapability {
    /// The reason mounts are unavailable, if any (`None` ⇒ mounts are possible).
    pub fn reason(&self) -> Option<&str> {
        match self {
            MountCapability::Available => None,
            MountCapability::Unavailable(reason) => Some(reason),
        }
    }
}

/// Probe the current process's mount capability without side effects.
///
/// Reads `CapEff` from `/proc/self/status` and checks `CAP_SYS_ADMIN`. This is
/// deliberately *not* a `mount` syscall probe: attempting a real mount to test
/// would mutate the host mount namespace.
pub fn probe_mount_capability() -> MountCapability {
    match fs::read_to_string("/proc/self/status") {
        Ok(status) => capability_from_status(&status),
        Err(err) => MountCapability::Unavailable(format!(
            "cannot read /proc/self/status to check CAP_SYS_ADMIN: {err}"
        )),
    }
}

/// Extract the capability verdict from `/proc/self/status` contents.
fn capability_from_status(status: &str) -> MountCapability {
    let Some(value) = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .map(str::trim)
    else {
        return MountCapability::Unavailable(
            "/proc/self/status has no CapEff line; cannot check CAP_SYS_ADMIN".to_string(),
        );
    };
    capability_from_cap_eff(value)
}

/// Check `CAP_SYS_ADMIN` in a hex `CapEff` mask.
fn capability_from_cap_eff(mask: &str) -> MountCapability {
    match u64::from_str_radix(mask, 16) {
        Ok(bits) if bits & (1 << CAP_SYS_ADMIN_BIT) != 0 => MountCapability::Available,
        Ok(_) => MountCapability::Unavailable(
            "process lacks CAP_SYS_ADMIN (run as root or delegate a mount namespace); \
             specs were assembled but not applied"
                .to_string(),
        ),
        Err(_) => MountCapability::Unavailable(format!(
            "unparseable CapEff mask {mask:?}; cannot check CAP_SYS_ADMIN"
        )),
    }
}

// ─── Application ────────────────────────────────────────────────

/// Performs one real mount. Injected so tests never touch the host.
pub trait MountRunner {
    /// Execute `spec`; the error string is surfaced verbatim to the operator.
    fn run(&self, spec: &MountSpec) -> Result<(), String>;
}

/// The real runner: shells out to `mount(8)`.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostMountRunner;

impl MountRunner for HostMountRunner {
    fn run(&self, spec: &MountSpec) -> Result<(), String> {
        let output = Command::new("mount")
            .args(spec.command_argv())
            .output()
            .map_err(|err| format!("cannot execute mount: {err}"))?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(if stderr.is_empty() {
            format!("mount failed with status {}", output.status)
        } else {
            stderr
        })
    }
}

/// One spec that was not applied, with the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountSkip {
    /// The spec that was skipped.
    pub spec: MountSpec,
    /// Why it was skipped (capability probe, missing source, runner error).
    pub reason: String,
}

/// Result of [`apply_mounts`].
#[derive(Debug, Clone, Default)]
pub struct MountOutcome {
    /// Specs that were actually mounted.
    pub applied: Vec<MountSpec>,
    /// Specs that were deliberately not attempted.
    pub skipped: Vec<MountSkip>,
    /// Specs the runner refused (a real failure, not a capability skip).
    pub failed: Vec<MountSkip>,
}

impl MountOutcome {
    /// Whether every spec was applied.
    pub fn all_applied(&self) -> bool {
        self.skipped.is_empty() && self.failed.is_empty()
    }
}

/// Apply `specs`, honestly reporting capability skips and real failures.
///
/// A bind source that does not exist on the host is skipped with a reason and is
/// never created (instanz must not invent host data). With an unavailable
/// capability nothing is attempted at all; each spec lands in
/// [`MountOutcome::skipped`] carrying the probe's reason.
pub fn apply_mounts(
    specs: &[MountSpec],
    capability: &MountCapability,
    runner: &dyn MountRunner,
) -> MountOutcome {
    let mut outcome = MountOutcome::default();

    if let Some(reason) = capability.reason() {
        for spec in specs {
            outcome.skipped.push(MountSkip {
                spec: spec.clone(),
                reason: reason.to_string(),
            });
        }
        return outcome;
    }

    for spec in specs {
        if spec.kind == MountKind::Bind && !spec.source.exists() {
            outcome.skipped.push(MountSkip {
                spec: spec.clone(),
                reason: format!(
                    "bind source {} does not exist on the host",
                    spec.source.display()
                ),
            });
            continue;
        }
        if !spec.target.exists() {
            outcome.skipped.push(MountSkip {
                spec: spec.clone(),
                reason: format!(
                    "mount target {} does not exist in the roof",
                    spec.target.display()
                ),
            });
            continue;
        }
        match runner.run(spec) {
            Ok(()) => outcome.applied.push(spec.clone()),
            Err(reason) => outcome.failed.push(MountSkip {
                spec: spec.clone(),
                reason,
            }),
        }
    }

    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn persistent_sources_plan_var_and_home_binds() {
        let root = Path::new("/runlevel/1/default");
        let sources =
            MountSources::new(Some(PathBuf::from("/srv/extos/var")), Some(PathBuf::from("/user")), false);
        let specs = plan_mounts(root, &sources);

        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0], MountSpec::bind("/srv/extos/var", root.join("var")));
        assert_eq!(specs[0].target, PathBuf::from("/runlevel/1/default/var"));
        assert_eq!(specs[1].kind, MountKind::Bind);
        assert_eq!(specs[1].source, PathBuf::from("/user"));
        assert_eq!(specs[1].target, root.join("home"));
        assert_eq!(
            specs[0].command_argv(),
            vec![
                "--bind".to_string(),
                "/srv/extos/var".to_string(),
                "/runlevel/1/default/var".to_string(),
            ]
        );
        assert!(specs[0].label().starts_with("bind /srv/extos/var -> "));
    }

    #[test]
    fn empty_sources_plan_nothing_and_tmpfs_is_opt_in() {
        let root = Path::new("/runlevel/1/default");
        assert!(plan_mounts(root, &MountSources::default()).is_empty());

        let sources = MountSources {
            var_tmpfs: true,
            ..MountSources::default()
        };
        let specs = plan_mounts(root, &sources);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].kind, MountKind::Tmpfs);
        assert_eq!(specs[0].source, PathBuf::from("tmpfs"));
        assert_eq!(specs[0].options, vec!["mode=0755"]);
        assert_eq!(
            specs[0].command_argv(),
            vec![
                "-t".to_string(),
                "tmpfs".to_string(),
                "-o".to_string(),
                "mode=0755".to_string(),
                "tmpfs".to_string(),
                "/runlevel/1/default/var".to_string(),
            ]
        );
    }

    #[test]
    fn capability_is_read_from_the_cap_eff_mask() {
        // Bit 21 set → CAP_SYS_ADMIN present.
        assert_eq!(capability_from_cap_eff("200000"), MountCapability::Available);
        // All bits set, including 21.
        assert_eq!(
            capability_from_cap_eff("000001ffffffffff"),
            MountCapability::Available
        );
        // No bit 21 → unavailable with an actionable reason.
        let capability = capability_from_cap_eff("00000000000000ff");
        assert!(capability.reason().is_some());
        assert!(capability.reason().unwrap().contains("CAP_SYS_ADMIN"));
        // Garbage is an explicit "cannot check", never a silent success.
        assert!(capability_from_cap_eff("zzz").reason().is_some());
        assert!(capability_from_cap_eff("").reason().is_some());
    }

    #[test]
    fn status_parsing_finds_cap_eff_and_rejects_missing_lines() {
        let status = "Name:\tinstanz\nCapEff:\t000001ffffffffff\n";
        assert!(capability_from_status(status).reason().is_none());
        let capability = capability_from_status("Name:\tinstanz\n");
        assert!(capability.reason().unwrap().contains("CapEff"));
    }

    /// Records every runner call so tests can prove invocation.
    #[derive(Default)]
    struct RecordingRunner {
        calls: RefCell<Vec<MountSpec>>,
        fail: bool,
    }

    impl MountRunner for RecordingRunner {
        fn run(&self, spec: &MountSpec) -> Result<(), String> {
            self.calls.borrow_mut().push(spec.clone());
            if self.fail {
                Err("mount: permission denied".to_string())
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn unavailable_capability_skips_everything_with_the_reason() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("var")).unwrap();
        fs::create_dir_all(root.join("home")).unwrap();
        let var_source = tmp.path().join("host-var");
        fs::create_dir_all(&var_source).unwrap();

        let sources = MountSources::new(Some(var_source.clone()), Some(PathBuf::from("/user")), false);
        let specs = plan_mounts(root, &sources);
        let runner = RecordingRunner::default();
        let outcome = apply_mounts(
            &specs,
            &MountCapability::Unavailable("process lacks CAP_SYS_ADMIN".into()),
            &runner,
        );

        assert!(outcome.applied.is_empty());
        assert!(outcome.failed.is_empty());
        assert_eq!(outcome.skipped.len(), 2);
        assert!(outcome
            .skipped
            .iter()
            .all(|skip| skip.reason.contains("CAP_SYS_ADMIN")));
        assert!(runner.calls.borrow().is_empty(), "no runner call when unavailable");
        assert!(!outcome.all_applied());
    }

    #[test]
    fn available_capability_invokes_the_runner_per_spec() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("var")).unwrap();
        fs::create_dir_all(root.join("home")).unwrap();
        let var_source = tmp.path().join("host-var");
        fs::create_dir_all(&var_source).unwrap();

        let sources = MountSources::new(Some(var_source.clone()), Some(root.to_path_buf()), false);
        let specs = plan_mounts(root, &sources);
        let runner = RecordingRunner::default();
        let outcome = apply_mounts(&specs, &MountCapability::Available, &runner);

        assert!(outcome.all_applied(), "{outcome:?}");
        assert_eq!(outcome.applied.len(), 2);
        assert_eq!(runner.calls.borrow().len(), 2);
        assert_eq!(runner.calls.borrow()[0].kind, MountKind::Bind);
    }

    #[test]
    fn missing_source_and_missing_target_are_skipped_not_invented() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // No var/ or home/ dirs and no host source: both binds are unappliable.
        let sources = MountSources::new(
            Some(root.join("absent-var")),
            Some(root.join("absent-home")),
            false,
        );
        let specs = plan_mounts(root, &sources);
        let runner = RecordingRunner::default();
        let outcome = apply_mounts(&specs, &MountCapability::Available, &runner);

        assert!(outcome.applied.is_empty());
        assert!(outcome.failed.is_empty());
        assert_eq!(outcome.skipped.len(), 2);
        assert!(outcome
            .skipped
            .iter()
            .all(|skip| skip.reason.contains("does not exist on the host")));
        assert!(!root.join("var").exists(), "apply must not create targets");

        // A spec whose source exists but whose roof target does not is skipped
        // with the roof-side reason (tmpfs has no host source to check).
        let var_dir = tmp.path().join("var-dir");
        fs::create_dir_all(&var_dir).unwrap();
        let specs = vec![MountSpec::tmpfs(root.join("var"), "0755")];
        let outcome = apply_mounts(&specs, &MountCapability::Available, &runner);
        assert_eq!(outcome.skipped.len(), 1);
        assert!(outcome.skipped[0]
            .reason
            .contains("does not exist in the roof"));
        assert!(runner.calls.borrow().is_empty());
    }

    #[test]
    fn runner_failures_are_reported_not_hidden() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("var")).unwrap();
        let specs = vec![MountSpec::tmpfs(root.join("var"), "0755")];
        let runner = RecordingRunner {
            fail: true,
            ..RecordingRunner::default()
        };
        let outcome = apply_mounts(&specs, &MountCapability::Available, &runner);
        assert_eq!(outcome.failed.len(), 1);
        assert!(outcome.failed[0].reason.contains("permission denied"));
        assert!(outcome.applied.is_empty());
    }
}
