//! Orphan `gen-<n>/` reaper (Phase-4 residual, task T3).
//!
//! `instanz apply` creates `gen-<n>` in step 4 and *records* it in
//! `generations.json` only in the last step. A run that dies in between (SIGINT,
//! disk full, a fatal post-weave error) leaves a generation directory that no
//! metadata references: an **orphan**. Because the next generation number is
//! `max(tracker.next, newest on disk + 1)` (`orchestrate::next_generation_number`),
//! every orphan also inflates the numbering forever, so they must be swept.
//!
//! # What is never deleted (type-level safety rules)
//!
//! 1. **The current generation** (`current` symlink) — never, whatever the
//!    metadata says.
//! 2. **Any generation recorded in `generations.json`** — the tracker is the
//!    authority for history, pins included.
//! 3. **Any generation a BLS entry still points at** (`gen-<n>.conf` from the
//!    snapshot engine, or `extos-<system>-g<n>-<kernel>.conf` from the forge
//!    matrix). A bootloader entry must never become a dangling file.
//! 4. **The youngest generation on disk** (`n == max(on_disk ∪ recorded)`).
//!    Reaping it would race an in-flight `apply` that has just created the
//!    directory and has not written its record yet; keeping the top slot makes
//!    the sweep safe to run while another apply is staged.
//!
//! Everything else — a `gen-<n>` directory with no record, not current, not
//! referenced by any entry, strictly below the youngest — is an orphan.
//!
//! # When it runs, and how it is turned off
//!
//! `apply` sweeps at the *end* (after the record is written and `current` has
//! switched), so this apply's own generation is always recorded before the
//! sweep looks at the tree. `EXTOS_REAPER=off` (also `0`/`false`/`no`)
//! disables the sweep entirely for operators who want manual control. Deletion
//! failures are reported per generation and never fail the apply.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::Context as _;
use libextos::snapshot::SnapshotEngine;
use libextos::snapshot::generation::GenerationTracker;

/// Environment variable that switches the sweep off (`off`, `0`, `false`, `no`).
pub const ENV_REAPER: &str = "EXTOS_REAPER";

/// One sweep's outcome.
#[derive(Debug, Clone, Default)]
pub struct ReapReport {
    /// The sweep was disabled by [`ENV_REAPER`].
    pub disabled: bool,
    /// Orphans selected for removal (ascending).
    pub candidates: Vec<u64>,
    /// Orphans actually removed (ascending).
    pub removed: Vec<u64>,
    /// Generations kept because they are recorded, current or BLS-referenced.
    pub referenced: Vec<u64>,
    /// Per-generation deletion failures (`gen-<n>: <error>`), never fatal.
    pub errors: Vec<String>,
}

impl ReapReport {
    /// One-line summary for the apply log.
    pub fn summary(&self) -> String {
        if self.disabled {
            return format!("disabled ({ENV_REAPER}=off)");
        }
        if self.candidates.is_empty() {
            return "no orphan generation".to_string();
        }
        format!(
            "{} orphan generation(s) removed{}",
            self.removed.len(),
            if self.errors.is_empty() {
                String::new()
            } else {
                format!(", {} failure(s)", self.errors.len())
            }
        )
    }
}

/// Whether the reaper is enabled (`EXTOS_REAPER` unset or anything but off-ish).
pub fn enabled() -> bool {
    match std::env::var(ENV_REAPER) {
        Ok(value) => !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "off" | "0" | "false" | "no" | "disabled"
        ),
        Err(_) => true,
    }
}

/// Generation number encoded in a BLS entry file name.
///
/// Understands both shapes this project writes:
///
/// * `<n>.conf`-style snapshot entries: `gen-<n>.conf`;
/// * forge matrix entries: `extos-<system>-g<n>-<kernel>.conf`.
///
/// Kernel labels may themselves contain `-g`, so the scan walks the `-g`
/// separators from the right and takes the first one followed by digits.
pub fn generation_from_entry_name(name: &str) -> Option<u64> {
    let stem = name.strip_suffix(".conf")?;
    if let Some(rest) = stem.strip_prefix("extos-") {
        return generation_after_gi(rest);
    }
    let rest = stem.strip_prefix("gen-")?;
    (!rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
        .then(|| rest.parse::<u64>().ok())
        .flatten()
}

/// `extos-a-b-g7-6.1-gentoo` → `Some(7)` (right-to-left `-g` scan).
fn generation_after_gi(text: &str) -> Option<u64> {
    let mut index = text.len();
    while let Some(found) = text[..index].rfind("-g") {
        let digits = &text[found + 2..];
        let take = digits.bytes().take_while(u8::is_ascii_digit).count();
        if take > 0 {
            let terminator_ok = digits[take..].starts_with('-') || digits[take..].is_empty();
            if terminator_ok {
                return digits[..take].parse::<u64>().ok();
            }
        }
        index = found;
        if index == 0 {
            break;
        }
    }
    None
}

/// Generation numbers referenced by BLS entries in `entries_dir`.
///
/// An unreadable directory yields an empty set: the caller then keeps its
/// recorded/current protections, so the failure mode is "reap less", never
/// "reap a bootloader-referenced tree".
pub fn bls_referenced(entries_dir: &Path) -> BTreeSet<u64> {
    let mut set = BTreeSet::new();
    let Ok(entries) = fs::read_dir(entries_dir) else {
        return set;
    };
    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str()
            && let Some(number) = generation_from_entry_name(name)
        {
            set.insert(number);
        }
    }
    set
}

/// Pure orphan selection (unit-testable, no filesystem access).
///
/// `on_disk` are the `gen-<n>` numbers present, `recorded` the numbers in
/// `generations.json`, `current` the `current` symlink target, `protected` the
/// BLS-referenced ones.
pub fn plan_reap(
    on_disk: &BTreeSet<u64>,
    recorded: &BTreeSet<u64>,
    current: Option<u64>,
    protected: &BTreeSet<u64>,
) -> Vec<u64> {
    let youngest = on_disk.iter().chain(recorded.iter()).copied().max();
    let Some(youngest) = youngest else {
        return Vec::new();
    };
    on_disk
        .iter()
        .copied()
        .filter(|number| !recorded.contains(number))
        .filter(|number| Some(*number) != current)
        .filter(|number| !protected.contains(number))
        .filter(|number| *number < youngest)
        .collect()
}

/// Sweep orphans under `rootfs`, protecting entries found in `bls_entries`.
///
/// Runs by default; see the module docs for the four protection rules. Returns
/// a report even when generations could not be deleted (errors are collected).
pub fn reap(rootfs: &Path, bls_entries: Option<&Path>) -> anyhow::Result<ReapReport> {
    if !enabled() {
        return Ok(ReapReport {
            disabled: true,
            ..ReapReport::default()
        });
    }

    let engine = SnapshotEngine::open(rootfs)
        .with_context(|| format!("cannot open the generations root {}", rootfs.display()))?;
    let tracker = GenerationTracker::open(rootfs)
        .with_context(|| format!("cannot read the generation tracker in {}", rootfs.display()))?;

    let on_disk: BTreeSet<u64> = engine
        .list()
        .with_context(|| format!("cannot list generations under {}", rootfs.display()))?
        .iter()
        .map(|snapshot| snapshot.generation)
        .collect();
    let recorded: BTreeSet<u64> = tracker.list().iter().map(|row| row.number).collect();
    let current = engine.current_generation()?;
    let protected = bls_entries.map(bls_referenced).unwrap_or_default();

    let mut report = ReapReport {
        referenced: on_disk
            .iter()
            .copied()
            .filter(|number| {
                recorded.contains(number) || Some(*number) == current || protected.contains(number)
            })
            .collect(),
        ..ReapReport::default()
    };
    report.candidates = plan_reap(&on_disk, &recorded, current, &protected);

    for number in &report.candidates {
        match engine.delete(*number) {
            Ok(()) => report.removed.push(*number),
            Err(error) => report.errors.push(format!("gen-{number}: {error}")),
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes the tests that call [`reap`] with the one that flips
    /// [`ENV_REAPER`]: `cargo test` runs unit tests in threads of one process,
    /// so an unguarded `set_var("off")` would disable a concurrent sweep.
    static REAPER_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        REAPER_ENV.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn numbers(values: &[u64]) -> BTreeSet<u64> {
        values.iter().copied().collect()
    }

    #[test]
    fn recorded_current_and_referenced_generations_are_kept() {
        let plan = plan_reap(
            &numbers(&[1, 2, 3, 4]),
            &numbers(&[1, 2, 4]),
            Some(4),
            &numbers(&[0]),
        );
        assert_eq!(plan, vec![3], "only the unrecorded, non-current gen-3");
    }

    #[test]
    fn the_youngest_generation_is_never_reaped() {
        // gen-4 is current, so remove it from the picture: gen-4 unrecorded and
        // not current but still the youngest → kept (in-flight apply window).
        let plan = plan_reap(
            &numbers(&[1, 2, 4]),
            &numbers(&[1, 2]),
            None,
            &BTreeSet::new(),
        );
        assert_eq!(plan, Vec::<u64>::new());

        // An older orphan is still collected.
        let plan = plan_reap(
            &numbers(&[1, 2, 3, 4]),
            &numbers(&[1, 2, 4]),
            None,
            &BTreeSet::new(),
        );
        assert_eq!(plan, vec![3]);
    }

    #[test]
    fn bls_referenced_generations_are_protected() {
        let plan = plan_reap(
            &numbers(&[1, 2, 3, 4, 5]),
            &numbers(&[1, 2, 5]),
            Some(5),
            &numbers(&[3]),
        );
        assert_eq!(plan, vec![4]);
    }

    #[test]
    fn empty_root_has_nothing_to_do() {
        assert!(plan_reap(&BTreeSet::new(), &BTreeSet::new(), None, &BTreeSet::new()).is_empty());
        // Recorded generations without directories do not invent candidates.
        assert!(
            plan_reap(
                &BTreeSet::new(),
                &numbers(&[1, 2]),
                Some(2),
                &BTreeSet::new()
            )
            .is_empty()
        );
    }

    #[test]
    fn entry_names_decode_both_bls_shapes() {
        assert_eq!(generation_from_entry_name("gen-7.conf"), Some(7));
        assert_eq!(
            generation_from_entry_name("extos-fixture-g4-6.11.0-extos.conf"),
            Some(4)
        );
        // A kernel label that itself contains `-g` must not shadow the number.
        assert_eq!(
            generation_from_entry_name("extos-edge-g12-6.1-gentoo.conf"),
            Some(12)
        );
        assert_eq!(generation_from_entry_name("loader.conf"), None);
        assert_eq!(generation_from_entry_name("extos-fixture.conf"), None);
        assert_eq!(generation_from_entry_name("gen-abc.conf"), None);
        assert_eq!(generation_from_entry_name("gen-1.txt"), None);
    }

    #[test]
    fn bls_referenced_reads_a_real_entries_directory() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("gen-3.conf"), "title x\n").unwrap();
        fs::write(tmp.path().join("extos-fixture-g5-6.11.0.conf"), "title y\n").unwrap();
        fs::write(tmp.path().join("notes.txt"), "ignored\n").unwrap();
        assert_eq!(bls_referenced(tmp.path()), numbers(&[3, 5]));
        assert!(bls_referenced(&tmp.path().join("absent")).is_empty());
    }

    #[test]
    fn reap_removes_an_orphan_and_keeps_the_current_generation() {
        let _guard = env_guard();
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let engine = SnapshotEngine::open(root).unwrap();
        let mut tracker = GenerationTracker::open(root).unwrap();

        // gen-1 recorded, gen-2 current and recorded, gen-3 orphan, gen-4
        // youngest/current.
        engine.create_empty(1).unwrap();
        engine.create_empty(2).unwrap();
        engine.create_empty(3).unwrap();
        engine.create_empty(4).unwrap();
        tracker.record(1, None, "first").unwrap();
        tracker.record(2, None, "second").unwrap();
        tracker.record(4, None, "fourth").unwrap();
        engine.switch_to(4).unwrap();

        let report = reap(root, None).unwrap();
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert_eq!(report.candidates, vec![3]);
        assert_eq!(report.removed, vec![3]);
        assert!(!engine.gen_path(3).exists(), "orphan must be gone");
        // Current generation and every recorded generation survive.
        for number in [1, 2, 4] {
            assert!(
                engine.gen_path(number).is_dir(),
                "gen-{number} must survive"
            );
        }
        assert_eq!(engine.current_generation().unwrap(), Some(4));
        assert!(report.summary().contains("1 orphan"));
    }

    #[test]
    fn reap_never_deletes_a_generation_referenced_by_a_bls_entry() {
        let _guard = env_guard();
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("system");
        let entries = tmp.path().join("boot/loader/entries");
        fs::create_dir_all(&entries).unwrap();
        let engine = SnapshotEngine::open(&root).unwrap();
        let mut tracker = GenerationTracker::open(&root).unwrap();

        engine.create_empty(1).unwrap();
        engine.create_empty(2).unwrap();
        engine.create_empty(3).unwrap();
        tracker.record(1, None, "first").unwrap();
        tracker.record(3, None, "third").unwrap();
        engine.switch_to(3).unwrap();
        // The user kept a boot entry for the unrecorded gen-2.
        fs::write(entries.join("extos-fixture-g2-6.11.0.conf"), "title x\n").unwrap();

        let report = reap(&root, Some(&entries)).unwrap();
        assert!(report.candidates.is_empty(), "{:?}", report.candidates);
        assert!(engine.gen_path(2).is_dir());
        assert!(report.referenced.contains(&2));
    }

    #[test]
    fn reaper_env_switch_disables_the_sweep() {
        let _guard = env_guard();
        // The whole test suite runs in one process, so set and restore the var.
        let previous = std::env::var_os(ENV_REAPER);
        // SAFETY: `set_var` is unsafe in edition 2024; the reaper tests are the
        // only writers of this variable and run sequentially per test binary.
        unsafe { std::env::set_var(ENV_REAPER, "off") };
        assert!(!enabled());
        let tmp = tempfile::tempdir().unwrap();
        let report = reap(tmp.path(), None).unwrap();
        assert!(report.disabled);
        assert!(report.candidates.is_empty());
        match previous {
            Some(value) => unsafe { std::env::set_var(ENV_REAPER, value) },
            None => unsafe { std::env::remove_var(ENV_REAPER) },
        }
        assert!(enabled());
    }
}
