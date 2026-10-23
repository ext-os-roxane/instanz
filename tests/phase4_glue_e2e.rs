//! CLI end-to-end tests for the Phase-4 residual glue (LANE L17):
//!
//! * **T1 — apply → runlevel-0 forge** (PLAN 4.2.6): a stub `mkinitcpio` shipped
//!   *inside the CAS* is derived as the blueprint tool, executed in the forge
//!   namespace, and its artifact plus the BLS matrix land in the caller's boot
//!   root. When no package ships the generator the forge is `skipped` and the
//!   generation records it.
//! * **T2 — `instanz run <profile>`** (PLAN 4.4.8): a statically linked program
//!   woven into the applied generation executes at level 0, and its exit code is
//!   propagated. Missing roof / program / bad level or backend are typed errors.
//! * **T3 — orphan `gen-<n>/` sweep**: an unrecorded generation left behind by
//!   an aborted apply is removed; BLS-referenced and current generations are not.
//!
//! Everything is synthesized at runtime in tempdirs: packages are stored with
//! `CasRepository::store_directory`, the config is a hand-written `.nix` file,
//! and `instanz` is spawned as a real process. No network, no root, no committed
//! blobs. Namespace-dependent tests print `SKIP` and return on hosts that cannot
//! create unprivileged user + mount namespaces (the reference host can).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use libextos::cas::CasRepository;
use libextos::forge::forge::{ForgeConfig, probe_unprivileged_userns};
use libextos::types::HashAlgorithm;

// ─── Fixtures ───────────────────────────────────────────────────

/// One package payload file: roof-relative path, bytes and mode.
type PayloadFile<'a> = (&'a str, &'a [u8], u32);

fn manifest(origin: &str, name: &str, version: &str) -> String {
    format!(
        r#"{{
  identity = {{ origin = "{origin}"; name = "{name}"; version = "{version}"; }};
  format = "extracted-tree";
  capabilities = {{ binaries = [ "{name}" ]; }};
  requires = [ ];
}}"#
    )
}

/// Store one package (payload + manifest + `<version>/current` ref) in the CAS.
fn publish(
    repo: &CasRepository,
    staging: &Path,
    origin: &str,
    name: &str,
    version: &str,
    files: &[PayloadFile<'_>],
) {
    let src = staging.join(format!("{origin}-{name}"));
    for (rel, bytes, mode) in files {
        let path = src.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(*mode)).unwrap();
    }
    let hash = repo.store_directory(&src).unwrap();
    repo.write_manifest(&hash, &manifest(origin, name, version))
        .unwrap();
    repo.create_ref(origin, name, version, &hash).unwrap();
    repo.update_current(origin, name, version).unwrap();
}

/// Stub generator: writes its argv and the staged `mkinitcpio.conf` into `-g`.
const STUB_MKINITCPIO: &str = r#"#!/bin/sh
# Stub mkinitcpio for the instanz apply→forge end-to-end test.
set -eu
out=""
cfg=""
all="$*"
while [ "$#" -gt 0 ]; do
  case "$1" in
    -g) out="${2:-}"; shift 2 || shift ;;
    -c) cfg="${2:-}"; shift 2 || shift ;;
    -k) shift 2 || shift ;;
    -p) shift 2 || shift ;;
    *) shift ;;
  esac
done
if [ -z "$out" ]; then
  echo "stub: missing -g" >&2
  exit 3
fi
{
  echo "stub-argv: $all"
  if [ -n "$cfg" ]; then
    echo "config-begin"
    cat "$cfg"
    echo "config-end"
  fi
} > "$out"
echo "stub stdout"
"#;

/// Write a system config with `body` inserted into the attribute set.
fn write_config(dir: &Path, packages: &[&str], body: &str) -> PathBuf {
    let config = dir.join("default.nix");
    let packages = packages
        .iter()
        .map(|package| format!("    \"{package}\""))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(
        &config,
        format!(
            r#"{{
  name = "fixture";
  packages = [
{packages}
  ];
{body}
}}"#
        ),
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
        .env_remove("EXTOS_MKINITCPIO")
        .env_remove("EXTOS_FORGE_NS")
        .env_remove("EXTOS_FORGE_UNSHARE")
        .env_remove("EXTOS_FORGE_SHELL")
        .env_remove("EXTOS_FORGE_HOST_DIRS")
        .env_remove("EXTOS_REAPER")
        .env_remove("EXTOS_MIRRORS_ARCHLINUX")
        .env_remove("EXTOS_MIRRORS_DEBIAN")
        .env_remove("EXTOS_CONTAINER_BACKEND")
        .env_remove("EXTOS_SYSTEM_CONFIG")
        .env_remove("EXTOS_CACHE_DIR")
        .env_remove("EXTOS_LDCONFIG")
        .env_remove("EXTOS_DEPMOD");
    cmd
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed (status {:?})\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status.code(),
        stdout(output),
        stderr(output)
    );
}

fn assert_failure(output: &Output, needle: &str) {
    assert!(
        !output.status.success(),
        "command unexpectedly succeeded\n--- stdout ---\n{}",
        stdout(output)
    );
    let err = stderr(output);
    assert!(
        err.contains(needle),
        "expected {needle:?} in stderr:\n{err}\n--- stdout ---\n{}",
        stdout(output)
    );
}

fn assert_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "expected to find {needle:?} in:\n{haystack}"
    );
}

/// A `depmod` stand-in: fixtures with a `boot.kernel` would otherwise run the
/// host tool against a tree that has no `lib/modules` yet.
fn depmod_stub(dir: &Path) -> PathBuf {
    let path = dir.join("depmod-stub");
    fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn namespaces_available() -> bool {
    match probe_unprivileged_userns(&ForgeConfig::default()) {
        Ok(()) => true,
        Err(error) => {
            eprintln!("SKIP: {error}");
            false
        }
    }
}

// ─── T1: apply → forge ──────────────────────────────────────────

#[test]
fn apply_forges_an_initramfs_and_writes_the_bls_matrix() {
    if !namespaces_available() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let repo = CasRepository::open(tmp.path().join("repository"), HashAlgorithm::Blake3).unwrap();
    let staging = tmp.path().join("_staging");
    fs::create_dir_all(&staging).unwrap();

    publish(
        &repo,
        &staging,
        "archlinux",
        "mkinitcpio-stub",
        "1.0.0",
        &[("usr/bin/mkinitcpio", STUB_MKINITCPIO.as_bytes(), 0o755)],
    );
    let config = write_config(
        tmp.path(),
        &["archlinux/mkinitcpio-stub=1.0.0"],
        r#"  boot = {
    kernel = "6.11.0-extos";
    modules = [ "ext4" ];
    cmdline = "quiet";
    initrd = "/boot/initramfs-extos.img";
  };
  linux = "/vmlinuz";"#,
    );
    let rootfs = tmp.path().join("system");
    let boot = tmp.path().join("boot");
    let scratch = tmp.path().join("scratch");
    let depmod = depmod_stub(tmp.path());

    let output = instanz(&repo.root)
        .arg("apply")
        .arg(&config)
        .arg("--rootfs")
        .arg(&rootfs)
        .arg("--boot-root")
        .arg(&boot)
        .env("EXTOS_FORGE_SCRATCH", &scratch)
        .env("EXTOS_DEPMOD", &depmod)
        .env("EXTOS_LDCONFIG", "extos-nonexistent-ldconfig-probe")
        .output()
        .unwrap();
    assert_success(&output);
    let out = stdout(&output);

    // The derivation is traced: the generator comes from the woven package.
    assert_contains(&out, "derived blueprint:");
    assert_contains(&out, "tools = [ { name = \"mkinitcpio\"; object =");
    assert_contains(&out, "exec = \"usr/bin/mkinitcpio\"");
    assert_contains(
        &out,
        "archlinux/mkinitcpio-stub provides usr/bin/mkinitcpio",
    );
    assert_contains(&out, "✓ forged");
    assert_contains(&out, "forge forged");
    assert_contains(&out, "✓ BLS entry");
    assert_contains(&out, "✓ loader.conf created");

    // Artifact harvested through the forge's read-write out bind.
    let artifact = boot.join("initramfs-extos.img");
    let metadata = fs::metadata(&artifact).expect("the forged initramfs must exist");
    assert!(metadata.len() > 0, "the artifact must not be empty");
    let body = fs::read_to_string(&artifact).unwrap();
    assert_contains(&body, "stub-argv: -g ");
    assert_contains(&body, "config-begin");
    assert_contains(&body, "HOOKS=(base udev modconf block filesystems ext4)");

    // BLS matrix entry, named from (system, generation, kernel).
    let entries = boot.join("loader/entries");
    let entry = entries.join("extos-fixture-g1-6.11.0-extos.conf");
    let text = fs::read_to_string(&entry).expect("the forge BLS entry must exist");
    assert_contains(&text, "title ExtOS fixture 6.11.0-extos");
    assert_contains(&text, "linux /vmlinuz");
    assert_contains(&text, "initrd /initramfs-extos.img");
    assert_contains(&text, "options quiet");

    // A fresh boot root is bootable: loader.conf defaults to the new entry.
    let loader = fs::read_to_string(boot.join("loader/loader.conf")).unwrap();
    assert_contains(&loader, "default extos-fixture-g1-6.11.0-extos");

    // The generation description records the forge outcome for the auditor.
    let listed = instanz(&repo.root)
        .arg("generations")
        .arg("--rootfs")
        .arg(&rootfs)
        .output()
        .unwrap();
    assert_success(&listed);
    let gens = stdout(&listed);
    assert_contains(&gens, "forge=forged, bls=1");
}

#[test]
fn apply_records_forge_skipped_when_no_package_ships_the_generator() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = CasRepository::open(tmp.path().join("repository"), HashAlgorithm::Blake3).unwrap();
    let staging = tmp.path().join("_staging");
    fs::create_dir_all(&staging).unwrap();

    publish(
        &repo,
        &staging,
        "archlinux",
        "base",
        "1.0.0",
        &[("usr/bin/hello", b"#!/bin/sh\n", 0o755)],
    );
    let config = write_config(
        tmp.path(),
        &["archlinux/base=1.0.0"],
        r#"  boot = { kernel = "6.11.0-extos"; initrd = "/boot/initramfs-extos.img"; };
  linux = "/vmlinuz";"#,
    );
    let rootfs = tmp.path().join("system");
    let boot = tmp.path().join("boot");
    let depmod = depmod_stub(tmp.path());

    let output = instanz(&repo.root)
        .arg("apply")
        .arg(&config)
        .arg("--rootfs")
        .arg(&rootfs)
        .arg("--boot-root")
        .arg(&boot)
        .env("EXTOS_DEPMOD", &depmod)
        .env("EXTOS_LDCONFIG", "extos-nonexistent-ldconfig-probe")
        .output()
        .unwrap();
    assert_success(&output);
    let out = stdout(&output);
    assert_contains(
        &out,
        "forge skipped: no woven package ships an executable `mkinitcpio`",
    );
    assert_contains(&out, "BLS entries skipped: the forge produced no initramfs");
    // A skipped forge writes no artifact and no boot entries (a BLS entry
    // pointing at a non-existent initramfs would be a lie).
    assert!(!boot.join("initramfs-extos.img").exists());
    assert!(!boot.join("loader/entries").exists());

    let listed = instanz(&repo.root)
        .arg("generations")
        .arg("--rootfs")
        .arg(&rootfs)
        .output()
        .unwrap();
    assert_success(&listed);
    assert_contains(&stdout(&listed), "forge=skipped, bls=0");
}

// ─── T2: instanz run ────────────────────────────────────────────

/// Compile a trivial statically linked program that exits with `code`.
///
/// A static binary needs no `/lib` inside the woven tree, so the test exercises
/// namespace setup and exit-code propagation instead of dynamic loading.
fn build_static_helper(dir: &Path, code: i32) -> Option<PathBuf> {
    let source = dir.join("probe.c");
    fs::write(&source, format!("int main(void) {{ return {code}; }}\n")).unwrap();
    let binary = dir.join("probe");
    let output = match Command::new("cc")
        .arg("-static")
        .arg("-o")
        .arg(&binary)
        .arg(&source)
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            eprintln!("SKIP: no C compiler for the static run probe: {error}");
            return None;
        }
    };
    if !output.status.success() {
        eprintln!(
            "SKIP: `cc -static` is unavailable: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return None;
    }
    Some(binary)
}

#[test]
fn run_executes_the_applied_tree_and_propagates_the_exit_code() {
    if !namespaces_available() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let Some(helper) = build_static_helper(tmp.path(), 7) else {
        return;
    };
    let repo = CasRepository::open(tmp.path().join("repository"), HashAlgorithm::Blake3).unwrap();
    let staging = tmp.path().join("_staging");
    fs::create_dir_all(&staging).unwrap();
    let bytes = fs::read(&helper).unwrap();
    publish(
        &repo,
        &staging,
        "archlinux",
        "probe",
        "1.0.0",
        &[("usr/bin/probe", &bytes, 0o755)],
    );
    let config = write_config(tmp.path(), &["archlinux/probe=1.0.0"], "");
    let rootfs = tmp.path().join("system");

    let applied = instanz(&repo.root)
        .arg("apply")
        .arg(&config)
        .arg("--rootfs")
        .arg(&rootfs)
        .env("EXTOS_LDCONFIG", "extos-nonexistent-ldconfig-probe")
        .output()
        .unwrap();
    assert_success(&applied);

    let run = instanz(&repo.root)
        .arg("run")
        .arg("probe")
        .arg("--rootfs")
        .arg(&rootfs)
        .arg("--program")
        .arg("/usr/bin/probe")
        .output()
        .unwrap();
    assert_eq!(
        run.status.code(),
        Some(7),
        "the container exit code must be propagated\n--- stdout ---\n{}\n--- stderr ---\n{}",
        stdout(&run),
        stderr(&run)
    );
    let out = stdout(&run);
    assert_contains(&out, "level     : 0 (isolated)");
    assert_contains(&out, "backend   : native");
    assert_contains(&out, "exit      : 7");
}

#[test]
fn run_reports_typed_errors_for_unusable_invocations() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = CasRepository::open(tmp.path().join("repository"), HashAlgorithm::Blake3).unwrap();
    let rootfs = tmp.path().join("system");

    // Never applied: no `current` generation.
    let missing = instanz(&repo.root)
        .arg("run")
        .arg("anything")
        .arg("--rootfs")
        .arg(&rootfs)
        .output()
        .unwrap();
    assert_failure(&missing, "run requires an applied system");

    // Applied, but the requested program is not in the roof.
    let staging = tmp.path().join("_staging");
    fs::create_dir_all(&staging).unwrap();
    publish(
        &repo,
        &staging,
        "archlinux",
        "base",
        "1.0.0",
        &[("usr/bin/hello", b"#!/bin/sh\n", 0o755)],
    );
    let config = write_config(tmp.path(), &["archlinux/base=1.0.0"], "");
    let applied = instanz(&repo.root)
        .arg("apply")
        .arg(&config)
        .arg("--rootfs")
        .arg(&rootfs)
        .env("EXTOS_LDCONFIG", "extos-nonexistent-ldconfig-probe")
        .output()
        .unwrap();
    assert_success(&applied);

    let absent = instanz(&repo.root)
        .arg("run")
        .arg("base")
        .arg("--rootfs")
        .arg(&rootfs)
        .arg("--program")
        .arg("/usr/bin/absent")
        .output()
        .unwrap();
    assert_failure(&absent, "is missing from the rootfs");

    let bad_level = instanz(&repo.root)
        .arg("run")
        .arg("base")
        .arg("--rootfs")
        .arg(&rootfs)
        .arg("--program")
        .arg("/usr/bin/hello")
        .arg("--level")
        .arg("9")
        .output()
        .unwrap();
    assert_failure(&bad_level, "invalid isolation level 9");

    let bad_backend = instanz(&repo.root)
        .arg("run")
        .arg("base")
        .arg("--rootfs")
        .arg(&rootfs)
        .arg("--program")
        .arg("/usr/bin/hello")
        .arg("--backend")
        .arg("not-a-backend")
        .output()
        .unwrap();
    assert_failure(&bad_backend, "unknown container backend");
}

// ─── Boot-entry mode validation ─────────────────────────────────

#[test]
fn boot_root_and_bls_dir_are_mutually_exclusive() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = CasRepository::open(tmp.path().join("repository"), HashAlgorithm::Blake3).unwrap();
    let config = tmp.path().join("unused.nix");

    for subcommand in ["apply", "rollback", "gc"] {
        let mut cmd = instanz(&repo.root);
        cmd.arg(subcommand);
        if subcommand == "apply" {
            cmd.arg(&config);
        }
        cmd.arg("--rootfs")
            .arg(tmp.path().join("system"))
            .arg("--boot-root")
            .arg(tmp.path().join("boot"))
            .arg("--bls-dir")
            .arg(tmp.path().join("boot/loader/entries"));
        let output = cmd.output().unwrap();
        assert_failure(
            &output,
            "both --boot-root/EXTOS_BLS_ROOT and --bls-dir/EXTOS_BLS_DIR are set",
        );
    }
}

// ─── T3: orphan generation sweep ────────────────────────────────

#[test]
fn apply_reaps_orphans_but_never_current_recorded_or_bls_referenced_generations() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = CasRepository::open(tmp.path().join("repository"), HashAlgorithm::Blake3).unwrap();
    let staging = tmp.path().join("_staging");
    fs::create_dir_all(&staging).unwrap();
    publish(
        &repo,
        &staging,
        "archlinux",
        "base",
        "1.0.0",
        &[("usr/bin/hello", b"#!/bin/sh\n", 0o755)],
    );
    let config = write_config(
        tmp.path(),
        &["archlinux/base=1.0.0"],
        r#"  linux = "/vmlinuz";"#,
    );
    let rootfs = tmp.path().join("system");
    let entries = tmp.path().join("boot/loader/entries");

    let apply = |extra_env: &[(&str, &str)]| {
        let mut cmd = instanz(&repo.root);
        cmd.arg("apply")
            .arg(&config)
            .arg("--rootfs")
            .arg(&rootfs)
            .arg("--bls-dir")
            .arg(&entries)
            .env("EXTOS_LDCONFIG", "extos-nonexistent-ldconfig-probe");
        for (key, value) in extra_env {
            cmd.env(key, value);
        }
        let output = cmd.output().unwrap();
        assert_success(&output);
        stdout(&output)
    };

    // gen-1: recorded + current.
    apply(&[]);
    assert!(rootfs.join("gen-1").is_dir());
    assert!(entries.join("gen-1.conf").is_file());

    // Simulate an apply that died after creating the directory: gen-2 has no
    // generation record. A user-kept boot entry references it.
    fs::create_dir_all(rootfs.join("gen-2/usr")).unwrap();
    fs::write(
        entries.join("extos-fixture-g2-6.11.0-extos.conf"),
        "title kept by the user\n",
    )
    .unwrap();

    // gen-3 is recorded and current; the referenced gen-2 must survive.
    let out = apply(&[]);
    assert!(
        !out.contains("reaped gen-2"),
        "a BLS-referenced generation must never be reaped:\n{out}"
    );
    assert!(rootfs.join("gen-2").is_dir(), "gen-2 must survive");
    assert!(rootfs.join("gen-3").is_dir());

    // Two genuinely unreferenced orphans below the youngest are collected.
    fs::create_dir_all(rootfs.join("gen-4/usr")).unwrap();
    fs::create_dir_all(rootfs.join("gen-5/usr")).unwrap();
    let out = apply(&[]);
    assert_contains(&out, "✓ reaped gen-4");
    assert_contains(&out, "✓ reaped gen-5");
    assert!(!rootfs.join("gen-4").exists());
    assert!(!rootfs.join("gen-5").exists());
    // Recorded, current and BLS-referenced generations are still there.
    for number in [1, 2, 3, 6] {
        assert!(
            rootfs.join(format!("gen-{number}")).is_dir(),
            "gen-{number} must survive"
        );
    }
    assert_eq!(
        fs::read_link(rootfs.join("current")).unwrap(),
        Path::new("gen-6")
    );

    // The kill switch is honoured end-to-end.
    fs::create_dir_all(rootfs.join("gen-7/usr")).unwrap();
    let out = apply(&[("EXTOS_REAPER", "off")]);
    assert_contains(&out, "orphan sweep: disabled (EXTOS_REAPER=off)");
    assert!(!out.contains("reaped gen-7"));
    // Numbering skips the orphan (max on disk + 1), which is exactly why the
    // sweep matters; gen-7 is still there because the operator disabled it.
    assert!(rootfs.join("gen-8").is_dir());
    assert!(rootfs.join("gen-7").is_dir());
}
