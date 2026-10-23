//! Full end-to-end test for PLAN sub-phase 4.1 "Runlevel 1 — Host System
//! Weaving": `instanz apply` driven as a real process through the whole chain
//!
//! ```text
//! groups/virtual expansion → SONAME anchor bidding → weave → /etc seeding
//!   → /var + /home mount spec → ldconfig/depmod hooks → lock + generation
//! ```
//!
//! Payloads are copied from the running host at test time (`/usr/bin/bash`,
//! `/usr/bin/true`, `libc.so.6`), with synthetic fallbacks when a path is
//! unavailable: nothing is committed, downloaded, or needs root. The only other
//! fixtures are hand-written `manifest.nix` files, a virtual ref, and two shell
//! stubs that record how the post-weave tools were invoked.
//!
//! The library-level half of the chain (anchor ranking against real SONAMEs and
//! the linker-law assertions) lives in `core/libextos/tests/system_e2e.rs`;
//! this file pins the *orchestration* half, which only exists in instanz.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use libextos::cas::CasRepository;
use libextos::elf_scan;
use libextos::types::HashAlgorithm;

// ─── Host payloads ──────────────────────────────────────────────

/// Copy the first readable candidate into `destination`, else write `fallback`.
fn copy_host_payload(destination: &Path, candidates: &[&str], fallback: &[u8]) {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    for candidate in candidates {
        if let Ok(bytes) = fs::read(candidate) {
            fs::write(destination, bytes).unwrap();
            return;
        }
    }
    fs::write(destination, fallback).unwrap();
}

/// SONAME of a staged payload, falling back to the given name.
fn soname_of(payload: &Path, fallback: &str) -> String {
    elf_scan::read_soname(payload).unwrap_or_else(|| fallback.to_string())
}

// ─── Fixture CAS ────────────────────────────────────────────────

struct Fixture<'a> {
    origin: &'a str,
    name: &'a str,
    version: &'a str,
    files: Vec<(&'a str, Payload)>,
    libraries: Vec<String>,
    binaries: Vec<String>,
}

/// Either literal text or the path of a file to copy into the payload.
enum Payload {
    Text(&'static str),
    CopyOf(PathBuf),
}

impl Fixture<'_> {
    fn manifest(&self) -> String {
        let quote = |values: &[String]| {
            values
                .iter()
                .map(|value| format!("\"{value}\""))
                .collect::<Vec<_>>()
                .join(" ")
        };
        format!(
            r#"{{
  identity = {{
    origin = "{}";
    name = "{}";
    version = "{}";
  }};
  format = "extracted-tree";
  capabilities = {{
    binaries = [ {} ];
    libraries = [ {} ];
  }};
  requires = [ ];
}}"#,
            self.origin,
            self.name,
            self.version,
            quote(&self.binaries),
            quote(&self.libraries)
        )
    }
}

fn publish(repo: &CasRepository, fixture: &Fixture<'_>, staging: &Path) {
    let src = staging.join(format!("{}-{}", fixture.origin, fixture.name));
    fs::create_dir_all(&src).unwrap();
    for (rel, payload) in &fixture.files {
        let destination = src.join(rel);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        match payload {
            Payload::Text(contents) => fs::write(&destination, contents).unwrap(),
            Payload::CopyOf(source) => {
                fs::copy(source, &destination).unwrap();
            }
        }
        if rel.starts_with("usr/bin/") || rel.starts_with("usr/lib/") {
            fs::set_permissions(&destination, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    let hash = repo.store_directory(&src).unwrap();
    repo.write_manifest(&hash, &fixture.manifest()).unwrap();
    repo.create_ref(fixture.origin, fixture.name, fixture.version, &hash)
        .unwrap();
    repo.update_current(fixture.origin, fixture.name, fixture.version)
        .unwrap();
}

/// The minimal system: glibc + bash + coreutils, with a competing libc provider
/// and a virtual `glibc` ref, exactly the shape PLAN 4.1.7 asks for.
struct World {
    _tmp: tempfile::TempDir,
    repo: CasRepository,
    config: PathBuf,
    var_dir: PathBuf,
    home_dir: PathBuf,
    soname: String,
}

fn build_world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let repo = CasRepository::open(root.join("repository"), HashAlgorithm::Blake3).unwrap();
    let staging = root.join("staging");
    fs::create_dir_all(&staging).unwrap();

    // Real payloads when available (this host has them).
    let libc = root.join("payload-libc");
    copy_host_payload(
        &libc,
        &["/usr/lib/libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6", "/lib/libc.so.6"],
        b"\x7fELF\x02\x01\x01\x00extos-synthetic-libc",
    );
    let soname = soname_of(&libc, "libc.so.6");
    let rival = root.join("payload-rival-libc");
    copy_host_payload(
        &rival,
        &["/usr/lib/libm.so.6", "/lib/x86_64-linux-gnu/libm.so.6"],
        b"\x7fELF\x02\x01\x01\x00extos-synthetic-rival",
    );
    let bash = root.join("payload-bash");
    copy_host_payload(
        &bash,
        &["/usr/bin/bash", "/bin/bash"],
        b"#!/bin/sh\necho extos-bash\n",
    );
    let true_bin = root.join("payload-true");
    copy_host_payload(
        &true_bin,
        &["/usr/bin/true", "/bin/true"],
        b"#!/bin/sh\nexit 0\n",
    );

    publish(
        &repo,
        &Fixture {
            origin: "archlinux",
            name: "glibc",
            version: "2.39",
            files: vec![
                (
                    "usr/lib/libc.so.6",
                    Payload::CopyOf(libc.clone()),
                ),
                ("etc/ld.so.conf", Payload::Text("include /etc/ld.so.conf.d/*.conf\n")),
            ],
            // The real SONAME read from the payload (via readelf or the name).
            libraries: vec![soname.clone()],
            binaries: vec![],
        },
        &staging,
    );
    publish(
        &repo,
        &Fixture {
            origin: "alpine",
            name: "musl",
            version: "1.2.5",
            files: vec![("usr/lib/libc.so.6", Payload::CopyOf(rival))],
            // Same SONAME, different payload: only bidding can arbitrate.
            libraries: vec![soname.clone()],
            binaries: vec![],
        },
        &staging,
    );
    publish(
        &repo,
        &Fixture {
            origin: "archlinux",
            name: "bash",
            version: "5.2",
            files: vec![
                ("usr/bin/bash", Payload::CopyOf(bash)),
                ("etc/bash.bashrc", Payload::Text("# ExtOS bash defaults\n")),
                ("etc/profile", Payload::Text("# ExtOS profile\n")),
            ],
            libraries: vec![],
            binaries: vec!["bash".to_string()],
        },
        &staging,
    );
    publish(
        &repo,
        &Fixture {
            origin: "archlinux",
            name: "coreutils",
            version: "9.4",
            files: vec![("usr/bin/true", Payload::CopyOf(true_bin))],
            libraries: vec![],
            binaries: vec!["true".to_string()],
        },
        &staging,
    );

    // `refs/virtual/glibc/current → ../../archlinux/glibc/2.39`.
    repo.create_virtual_ref("glibc", "current", "archlinux", "glibc")
        .unwrap();

    let var_dir = root.join("host-var");
    let home_dir = root.join("host-home");
    fs::create_dir_all(&var_dir).unwrap();
    fs::create_dir_all(&home_dir).unwrap();

    let config = root.join("minimal.nix");
    fs::write(
        &config,
        format!(
            r#"{{
  name = "minimal";
  native_pm = "debian";
  boot = {{
    kernel = "6.8.2-extos";
    modules = [ "ext4" ];
    cmdline = "quiet nowatchdog";
  }};
  groups = {{
    core = [ "archlinux/bash=5.2" {{ virtual = "glibc"; }} ];
    base = [ "@core" "archlinux/coreutils=9.4" ];
  }};
  packages = [
    "@base"
    "alpine/musl=1.2.5"
  ];
  var = "{}";
  home = "{}";
  services = [ "sshd" ];
}}
"#,
            var_dir.display(),
            home_dir.display(),
        ),
    )
    .unwrap();

    World {
        _tmp: tmp,
        repo,
        config,
        var_dir,
        home_dir,
        soname,
    }
}

// ─── Process helpers ────────────────────────────────────────────

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
        .env_remove("EXTOS_MIRRORS_ALPINE")
        .env_remove("EXTOS_MIRRORS_RPM")
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

fn assert_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "expected to find {needle:?} in:\n{haystack}"
    );
}

/// A tool stub that records its argv and whether the weave had already happened.
fn write_hook_stub(path: &Path, log: &Path) -> PathBuf {
    fs::write(
        path,
        format!(
            "#!/bin/sh\n\
             if [ -e \"$2/usr/bin/bash\" ]; then woven=yes; else woven=no; fi\n\
             printf '%s argv=%s woven=%s\\n' \"$0\" \"$*\" \"$woven\" >> '{}'\n",
            log.display()
        ),
    )
    .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    path.to_path_buf()
}

// ─── The test ───────────────────────────────────────────────────

#[test]
fn minimal_system_weaves_through_the_full_4_1_chain() {
    let world = build_world();
    let rootfs = world._tmp.path().join("runlevel/1/minimal");
    let hook_log = world._tmp.path().join("hooks.log");
    let ldconfig = write_hook_stub(&world._tmp.path().join("ldconfig-stub"), &hook_log);
    let depmod = write_hook_stub(&world._tmp.path().join("depmod-stub"), &hook_log);

    let output = instanz(&world.repo.root)
        .arg("apply")
        .arg(&world.config)
        .arg("--rootfs")
        .arg(&rootfs)
        .env("EXTOS_LDCONFIG", &ldconfig)
        .env("EXTOS_DEPMOD", &depmod)
        .output()
        .unwrap();
    assert_success(&output);
    let out = stdout(&output);

    // ── 4.1.1 boot block is parsed and reported through the pipeline ──
    assert_contains(&out, "[1/11] expand");
    // ── 4.1.2 groups + virtual refs flatten to concrete refs ──────────
    assert_contains(&out, "@core → 2");
    assert_contains(&out, "@base → 3");
    assert_contains(&out, "virtual/glibc → archlinux/glibc 2.39");
    assert_contains(&out, "4 expanded ref(s), 4 present, 0 missing");
    // ── 4.1.3 the anchor, not the origin order, owns the contested lib ─
    if !world.soname.is_empty() {
        assert_contains(
            &out,
            &format!(
                "anchor {} → archlinux/glibc (priority 10, over alpine/musl)",
                world.soname
            ),
        );
    }

    // ── Weave ─────────────────────────────────────────────────────────
    let tree = rootfs.join("gen-1");
    assert!(tree.join("usr/bin/bash").exists());
    assert!(tree.join("usr/bin/true").exists());
    let woven_libc = tree.join(format!("usr/lib/{}", world.soname));
    assert!(woven_libc.exists(), "{} missing", woven_libc.display());
    let winner_hash = world
        .repo
        .resolve_ref("archlinux", "glibc", "2.39")
        .unwrap();
    let winner_bytes = fs::read(
        world
            .repo
            .object_path(&winner_hash)
            .join(format!("content/usr/lib/{}", world.soname)),
    )
    .unwrap();
    assert_eq!(
        fs::read(&woven_libc).unwrap(),
        winner_bytes,
        "the anchor winner's payload must be woven"
    );

    // ── 4.1.4 /etc seeding ───────────────────────────────────────────
    // On a greenfield generation the weaver itself already materialized the
    // packaged defaults, so seeding is a no-op that records skips — it must
    // never rewrite what the weave (or the operator) put there.
    assert_contains(&out, "[6/11] seed /etc");
    assert_contains(&out, "0 seeded, 3 kept (already present)");
    assert_eq!(
        fs::read_to_string(tree.join("etc/profile")).unwrap(),
        "# ExtOS profile\n"
    );
    assert_eq!(
        fs::read_to_string(tree.join("etc/bash.bashrc")).unwrap(),
        "# ExtOS bash defaults\n"
    );
    assert!(tree.join("etc/ld.so.conf").exists());

    // ── 4.1.5 mount spec: assembled, and honestly skipped or applied ──
    assert_contains(&out, "[8/11] /var + /home mounts");
    assert!(
        out.contains(&format!("bind {} -> {}/var", world.var_dir.display(), tree.display()))
            || out.contains("mounted bind"),
        "var mount spec missing from:\n{out}"
    );
    assert!(
        out.contains(&format!(
            "bind {} -> {}/home",
            world.home_dir.display(),
            tree.display()
        )) || out.contains("mounted bind"),
        "home mount spec missing from:\n{out}"
    );
    assert!(
        !out.contains("✗ failed"),
        "mount failures must be reported, not invented:\n{out}"
    );

    // ── 4.1.6 hooks ran after the weave, scoped to the roof ───────────
    let log = fs::read_to_string(&hook_log).unwrap();
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(lines.len(), 2, "{log}");
    assert!(lines[0].contains(&format!("-r {}", tree.display())), "{log}");
    assert!(
        lines[1].contains(&format!("-b {} 6.8.2-extos", tree.display())),
        "{log}"
    );
    assert!(
        lines.iter().all(|line| line.contains("woven=yes")),
        "hooks must run after the weave:\n{log}"
    );

    // ── lockfile pins the expanded refs (virtual resolved concretely) ─
    let lock = fs::read_to_string(tree.join(".lock")).unwrap();
    for package in ["archlinux/bash", "archlinux/glibc", "archlinux/coreutils", "alpine/musl"] {
        assert_contains(&lock, package);
    }
    assert_contains(&out, "✓ generation 1 is now current");

    // ── Second apply: edited files survive, drifted files are restored ─
    fs::write(tree.join("etc/profile"), "# hand-edited by the operator\n").unwrap();
    // The operator (or a botched upgrade) removed a default: seeding repairs it.
    fs::remove_file(tree.join("etc/bash.bashrc")).unwrap();
    let second = instanz(&world.repo.root)
        .arg("apply")
        .arg(&world.config)
        .arg("--rootfs")
        .arg(&rootfs)
        .env("EXTOS_LDCONFIG", &ldconfig)
        .env("EXTOS_DEPMOD", &depmod)
        .output()
        .unwrap();
    assert_success(&second);
    let out = stdout(&second);
    // gen-2 is a snapshot of gen-1 and the weave re-materializes every packaged
    // file, so seeding again records skips only — it must never clobber.
    assert_contains(&out, "0 seeded, 3 kept (already present)");
    assert_contains(&out, "etc seed skipped etc/profile");
    assert_contains(&out, "never overwritten");

    let gen2 = rootfs.join("gen-2");
    assert_eq!(
        fs::read_to_string(gen2.join("etc/profile")).unwrap(),
        "# hand-edited by the operator\n",
        "seeding must never clobber an edited file"
    );
    // The deleted default is back with its packaged contents (the weaver owns
    // re-materialization; seeding is the non-destructive complement).
    assert_eq!(
        fs::read_to_string(gen2.join("etc/bash.bashrc")).unwrap(),
        "# ExtOS bash defaults\n"
    );
    // …and the untouched default is unchanged.
    assert!(gen2.join("etc/ld.so.conf").exists());
    assert_eq!(
        fs::read_link(rootfs.join("current")).unwrap(),
        Path::new("gen-2")
    );

    // No CAS path leaks into the woven tree (linker law).
    assert_no_cas_paths(&gen2, &world.repo.root);
}

/// Walk `root` and assert no symlink target points into the CAS.
fn assert_no_cas_paths(root: &Path, cas_root: &Path) {
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let meta = fs::symlink_metadata(&path).unwrap();
            if meta.file_type().is_symlink() {
                let target = fs::read_link(&path).unwrap();
                assert!(
                    !target.starts_with(cas_root) && !target.to_string_lossy().contains("/repository"),
                    "{} links into the CAS: {}",
                    path.display(),
                    target.display()
                );
            } else if meta.is_dir() {
                pending.push(path);
            }
        }
    }
}
