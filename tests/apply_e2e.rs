//! CLI end-to-end tests for PLAN Sub-phase 2.5 (tasks 2.5.1 – 2.5.6).
//!
//! Every fixture is synthesized at test runtime into tempdirs: a temporary CAS
//! repository is populated with `CasRepository::store_directory` + a
//! hand-written `manifest.nix`, and `instanz` is spawned as a real process
//! (`CARGO_BIN_EXE_instanz`) against a temporary generations root. No network,
//! no root, no committed blobs, and nothing outside the tempdir is touched —
//! `EXTOS_ROOTFS`, `EXTOS_BLS_DIR` and the mirror variables are cleared.
//!
//! Covered here:
//! * 2.5.1 `evaluate` — parse → resolve → DAG/plan summary, exit 0.
//! * 2.5.2 `apply` — snapshot → plan → weave → phantom → tools → lockfile →
//!   generation record, with explicit skip lines for unavailable tools.
//! * 2.5.3 `rollback` — `prev` moves `current` back without any BLS dir.
//! * 2.5.4 `gc` — two clearly reported stages.
//! * 2.5.5 `generations` — timestamps, package lists and the current marker.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use libextos::cas::CasRepository;
use libextos::types::HashAlgorithm;

// ─── Fixtures ───────────────────────────────────────────────────

/// A synthetic package: identity, payload (`rel path → contents`) and the
/// optional manifest fragments (`requires`, `phantom_spoofs`).
struct Fixture<'a> {
    origin: &'a str,
    name: &'a str,
    version: &'a str,
    files: Vec<(&'a str, &'a str)>,
    requires: &'a str,
    spoofs: &'a str,
}

impl Fixture<'_> {
    fn manifest(&self) -> String {
        format!(
            r#"{{
  identity = {{
    origin = "{origin}";
    name = "{name}";
    version = "{version}";
  }};
  format = "extracted-tree";
  capabilities = {{ binaries = [ "{name}" ]; }};
  requires = [ {requires} ];
  {spoofs}
}}"#,
            origin = self.origin,
            name = self.name,
            version = self.version,
            requires = self.requires,
            spoofs = self.spoofs,
        )
    }
}

/// Materialize `fixture` into `repo` and commit its ref + `<version>/current`.
fn publish(repo: &CasRepository, fixture: &Fixture<'_>, staging: &Path) {
    let src = staging.join(format!("{}-{}", fixture.origin, fixture.name));
    for (rel, contents) in &fixture.files {
        let path = src.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, contents).unwrap();
        if rel.starts_with("usr/bin/") {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    fs::create_dir_all(&src).unwrap();

    let hash = repo.store_directory(&src).unwrap();
    repo.write_manifest(&hash, &fixture.manifest()).unwrap();
    repo.create_ref(fixture.origin, fixture.name, fixture.version, &hash)
        .unwrap();
    repo.update_current(fixture.origin, fixture.name, fixture.version)
        .unwrap();
}

/// Three packages:
/// * `archlinux/alpha` — a binary + a library, declares a Debian `libc6` spoof;
/// * `archlinux/beta`  — depends on `alpha` (StrictPin, one DAG edge);
/// * `debian/gamma`    — a data file, so the tree is multi-origin.
///
/// The `spoofs` field is a manifest fragment, so the apply test can assert that
/// `native_pm = "debian"` produces a `libc6` dpkg row for an Arch package.
fn build_repo(root: &Path) -> CasRepository {
    let repo = CasRepository::open(root, HashAlgorithm::Blake3).unwrap();
    let staging = root.join("_staging");
    fs::create_dir_all(&staging).unwrap();

    publish(
        &repo,
        &Fixture {
            origin: "archlinux",
            name: "alpha",
            version: "1.0.0",
            files: vec![
                ("usr/bin/alpha", "#!/bin/sh\necho alpha\n"),
                ("usr/lib/libalpha.so.1", "ALPHA-SO-1"),
                // A packaged systemd unit so the PLAN 7.2.2 service reconcile
                // can actually enable the fixture's declared `sshd` service.
                ("usr/lib/systemd/system/sshd.service", "[Unit]\nDescription=fixture sshd\n"),
            ],
            requires: "",
            spoofs: r#"phantom_spoofs = { debian = [ { name = "libc6"; version = "2.39-0extos1"; } ]; };"#,
        },
        &staging,
    );
    publish(
        &repo,
        &Fixture {
            origin: "archlinux",
            name: "beta",
            version: "2.0.0",
            files: vec![("usr/bin/beta", "#!/bin/sh\necho beta\n")],
            requires: r#"{ origin = "archlinux"; name = "alpha"; version = "1.0.0"; }"#,
            spoofs: "",
        },
        &staging,
    );
    publish(
        &repo,
        &Fixture {
            origin: "debian",
            name: "gamma",
            version: "3.0.0",
            files: vec![("usr/bin/gamma", "#!/bin/sh\necho gamma\n"), ("usr/share/gamma/data", "gamma-db\n")],
            requires: "",
            spoofs: "",
        },
        &staging,
    );

    repo
}

/// Write `default.nix` next to the repository fixture.
fn write_config(tmp: &Path) -> PathBuf {
    let config = tmp.join("default.nix");
    fs::write(
        &config,
        r#"{
  name = "fixture";
  native_pm = "debian";
  packages = [
    "archlinux/alpha=1.0.0"
    "archlinux/beta=2.0.0"
    "debian/gamma=3.0.0"
  ];
  services = [ "sshd" ];
}
"#,
    )
    .unwrap();
    config
}

// ─── Process helpers ────────────────────────────────────────────

/// An `instanz` invocation with ambient configuration neutralized.
fn instanz(repository: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_instanz"));
    cmd.arg("--repository")
        .arg(repository)
        .env_remove("EXTOS_REPOSITORY")
        .env_remove("EXTOS_ROOTFS")
        .env_remove("EXTOS_BLS_DIR")
        .env_remove("EXTOS_BLS_ROOT")
        .env_remove("EXTOS_FORGE_SCRATCH")
        .env_remove("EXTOS_MIRRORS_ARCHLINUX")
        .env_remove("EXTOS_MIRRORS_DEBIAN")
        .env_remove("EXTOS_CACHE_DIR")
        .env_remove("EXTOS_DEPMOD");
    cmd
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Fail with the captured streams when a command did not exit 0.
fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed (status {:?})\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status.code(),
        stdout(output),
        stderr(output)
    );
}

fn assert_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "expected to find {needle:?} in:\n{haystack}"
    );
}

// ─── 2.5.1 evaluate ─────────────────────────────────────────────

#[test]
fn evaluate_prints_dag_and_plan_without_touching_a_rootfs() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = build_repo(&tmp.path().join("repository"));
    let config = write_config(tmp.path());

    let output = instanz(&repo.root).arg("evaluate").arg(&config).output().unwrap();
    assert_success(&output);
    let out = stdout(&output);

    // One row per package, including the multi-origin one.
    assert_contains(&out, "archlinux/alpha 1.0.0");
    assert_contains(&out, "archlinux/beta 2.0.0");
    assert_contains(&out, "debian/gamma 3.0.0");
    // The DAG has one edge: beta → alpha.
    assert_contains(&out, "DAG (3 node(s), 1 edge(s))");
    assert_contains(&out, "Plan:");
    assert_contains(&out, "collisions 0");
    assert_contains(&out, "warnings 0");
    // Roof PM came from the config.
    assert_contains(&out, "Roof native PM: debian");
    assert_contains(&out, "Services      : sshd");
    // Nothing was woven and no generations root exists.
    assert!(!tmp.path().join("system").exists());
    assert!(!stderr(&output).contains("error"));
    assert!(!stderr(&output).contains("panicked"));
}

// ─── 2.5.2 apply + 2.5.5 generations ───────────────────────────

#[test]
fn apply_weaves_phantoms_and_records_a_generation() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = build_repo(&tmp.path().join("repository"));
    let config = write_config(tmp.path());
    let rootfs = tmp.path().join("system");

    let output = instanz(&repo.root)
        .arg("apply")
        .arg(&config)
        .arg("--rootfs")
        .arg(&rootfs)
        // Force the "tool absent" path deterministically (no host dependency).
        .env("EXTOS_LDCONFIG", "extos-nonexistent-ldconfig-probe")
        .output()
        .unwrap();
    assert_success(&output);
    let out = stdout(&output);

    // Progress lines for every stage of the Phase-4 pipeline (4.1.1 – 4.1.6).
    for step in [
        "[1/11] expand",
        "[2/11] fetch missing packages",
        "[3/11] plan",
        "[4/11] snapshot before weave",
        "[5/11] weave",
        "[6/11] seed /etc",
        "[7/11] phantom rows",
        "[8/11] /var + /home mounts",
        "[9/11] post-weave tools",
        "[10/11] runlevel-0 forge",
        "[11/11] lockfile + generation record",
    ] {
        assert_contains(&out, step);
    }
    // No boot root is configured and no package ships a generator: the forge
    // says so loudly instead of silently doing nothing.
    assert_contains(&out, "forge skipped: no boot root configured");
    assert_contains(&out, "orphan sweep: no orphan generation");
    // No /etc payload and no mount sources in this fixture: both are announced.
    assert_contains(&out, "0 seeded, 0 kept (already present)");
    assert_contains(&out, "no mount sources declared");
    // PLAN 7.2.2: the declared `sshd` service is enabled during step 6 —
    // its unit ships with `archlinux/alpha`, so the reconcile creates the
    // relative wants symlink with zero warnings.
    assert_contains(&out, "services: 1 enabled, 0 disabled, 0 warning(s)");
    // Already-cached refs never hit the network.
    assert_contains(&out, "0 fetched, 3 already in the CAS");
    assert!(!out.contains("cannot fetch"));

    // The woven tree exists and is independent of the CAS path.
    let tree = rootfs.join("gen-1");
    assert!(tree.join("usr/bin").is_dir());
    assert!(tree.join("usr/bin/alpha").symlink_metadata().is_ok());
    assert!(tree.join("usr/bin/beta").symlink_metadata().is_ok());
    assert!(tree.join("usr/bin/gamma").symlink_metadata().is_ok());
    assert_eq!(
        fs::read_to_string(tree.join("usr/share/gamma/data")).unwrap(),
        "gamma-db\n"
    );

    // PLAN 7.2.2: the enabled service is a relative wants symlink into the
    // roof's FHS unit directory, and the marker records exactly this set.
    let wants_link = tree
        .join("etc/systemd/system/multi-user.target.wants")
        .join("sshd.service");
    assert_eq!(
        fs::read_link(&wants_link).unwrap(),
        Path::new("../../../../usr/lib/systemd/system/sshd.service")
    );
    assert!(wants_link.is_file(), "the relative target resolves inside the roof");
    assert_eq!(
        fs::read_to_string(tree.join("etc/systemd/.extos-enabled-services")).unwrap(),
        "sshd\n"
    );

    // `current` points at the new generation.
    let current = fs::read_link(rootfs.join("current")).unwrap();
    assert_eq!(current, Path::new("gen-1"));

    // Canonical phantom row (Arch) for the Arch packages…
    let pacman_db = tree.join("var/lib/pacman/local");
    let mut arch_desc = String::new();
    for entry in fs::read_dir(&pacman_db).unwrap() {
        let desc = entry.unwrap().path().join("desc");
        if desc.exists() {
            arch_desc.push_str(&fs::read_to_string(&desc).unwrap());
        }
    }
    assert_contains(&arch_desc, "%NAME%\nalpha");
    assert_contains(&arch_desc, "extos-phantom");

    // …and the spoofed Debian row, because `native_pm = "debian"`.
    let dpkg_status = fs::read_to_string(tree.join("var/lib/dpkg/status")).unwrap();
    assert_contains(&dpkg_status, "Package: libc6");
    assert_contains(&dpkg_status, "X-ExtOS-Phantom: extos-phantom");
    assert_contains(&dpkg_status, "Package: gamma");

    // Missing tools are announced, never silent.
    assert_contains(&out, "ldconfig skipped");
    assert_contains(&out, "depmod skipped");

    // Lockfile: concrete hashes for every declared ref.
    let lock = fs::read_to_string(tree.join(".lock")).unwrap();
    for package in ["archlinux/alpha", "archlinux/beta", "debian/gamma"] {
        assert_contains(&lock, package);
    }
    assert_contains(&lock, "hash = ");

    // 2.5.5: generations lists the new entry and marks it current.
    let listed = instanz(&repo.root)
        .arg("generations")
        .arg("--rootfs")
        .arg(&rootfs)
        .output()
        .unwrap();
    assert_success(&listed);
    let gens = stdout(&listed);
    assert_contains(&gens, "* gen-1");
    assert_contains(&gens, "3 package(s)");
    assert_contains(&gens, "archlinux/alpha");
    assert_contains(&gens, "UTC");
}

// ─── 2.5.3 rollback + 2.5.4 gc ─────────────────────────────────

#[test]
fn rollback_and_gc_manage_generations_without_a_bls_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = build_repo(&tmp.path().join("repository"));
    let config = write_config(tmp.path());
    let rootfs = tmp.path().join("system");

    let apply = |rootfs: &Path| {
        let output = instanz(&repo.root)
            .arg("apply")
            .arg(&config)
            .arg("--rootfs")
            .arg(rootfs)
            .env("EXTOS_LDCONFIG", "extos-nonexistent-ldconfig-probe")
            .output()
            .unwrap();
        assert_success(&output);
        stdout(&output)
    };

    // Two generations.
    assert_contains(&apply(&rootfs), "generation 1 is now current");
    assert_contains(&apply(&rootfs), "generation 2 is now current");
    assert_eq!(fs::read_link(rootfs.join("current")).unwrap(), Path::new("gen-2"));

    // 2.5.3: rollback to the previous generation (symlink-only mode).
    let rolled = instanz(&repo.root)
        .arg("rollback")
        .arg("--generation")
        .arg("prev")
        .arg("--rootfs")
        .arg(&rootfs)
        .output()
        .unwrap();
    assert_success(&rolled);
    let out = stdout(&rolled);
    assert_contains(&out, "rollback: generation 2 → 1");
    assert_contains(&out, "BLS default skipped: EXTOS_BLS_DIR is not set");
    assert_eq!(fs::read_link(rootfs.join("current")).unwrap(), Path::new("gen-1"));

    // A third apply snapshots the *rolled-back* tree, so a new gen-3 appears.
    assert_contains(&apply(&rootfs), "generation 3 is now current");

    // 2.5.4: both GC stages are reported; gen-1/gen-2 are older than keep=1
    // and gen-3 is current, so both are purged.
    let collected = instanz(&repo.root)
        .arg("gc")
        .arg("--keep")
        .arg("1")
        .arg("--rootfs")
        .arg(&rootfs)
        .output()
        .unwrap();
    assert_success(&collected);
    let out = stdout(&collected);
    assert_contains(&out, "stage 1/2: generations (keep 1)");
    assert_contains(&out, "purged 2 generation(s): gen-1, gen-2");
    assert_contains(&out, "stage 2/2: CAS objects");
    assert_contains(&out, "unreferenced object(s)");

    assert!(!rootfs.join("gen-1").exists());
    assert!(!rootfs.join("gen-2").exists());
    assert!(rootfs.join("gen-3").is_dir());
    assert_eq!(fs::read_link(rootfs.join("current")).unwrap(), Path::new("gen-3"));
}
