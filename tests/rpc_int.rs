//! Integration tests for the `instanz` gRPC control plane (PLAN 8.1.4).
//!
//! The server is driven in-process through the REAL tonic stack over a tmpdir
//! UDS: `rpc::serve` runs on a background OS thread with its own explicit
//! multi-thread runtime (exactly the `instanz serve` path — CAS open, runtime
//! build, UDS bind with the §15 mode, `serve_with_incoming`), and the
//! generated `InstanzServiceClient` connects through a `unix://` `Endpoint`.
//!
//! The module is compiled in from `src/` with `#[path]` because instanz is a
//! pure binary crate (no lib target to link against). The server module pulls
//! its real dependency cluster (`orchestrate`, `run`, `system`, `forge`,
//! `mount`, `reaper`); those are declared here under the same module names as
//! `main.rs` uses, so every `crate::…` path resolves in this test crate
//! exactly as in the binary. That also re-runs the included modules' in-module
//! unit tests inside this binary (the `pkt` `server_int` convention), and
//! `dead_code` is silenced for the cluster members the tests do not reach.
//!
//! Fixtures are synthesized at test runtime (the `tests/apply_e2e.rs`
//! construction: `CasRepository::store_directory` + hand-written
//! `manifest.nix`), no network is touched (every ref is pre-published, so the
//! fetch step reports "0 fetched"), and no test touches the filesystem outside
//! its tmpdir. The apply pipeline's progress lines print from the serve thread
//! and are therefore not captured by libtest's per-test capture — the same
//! output the real daemon writes to its stdout.

#![allow(dead_code)]

#[path = "../src/forge.rs"]
mod forge;
#[path = "../src/mount.rs"]
mod mount;
#[path = "../src/reaper.rs"]
mod reaper;
#[path = "../src/rpc.rs"]
mod rpc;
#[path = "../src/run.rs"]
mod run;
#[path = "../src/orchestrate.rs"]
mod orchestrate;
#[path = "../src/system.rs"]
mod system;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use libextos::cas::CasRepository;
use libextos::pb::extos::common::ErrorCode;
use libextos::pb::extos::instanz::instanz_service_client::InstanzServiceClient;
use libextos::pb::extos::instanz::{
    ApplyRequest, ContainerRequest, GenerationsRequest, IsolationLevel, PreviousGeneration,
    RollbackRequest, rollback_request,
};
use libextos::types::HashAlgorithm;
use tonic::transport::Endpoint;

use rpc::{InstanzConfig, ServeError};

// ─── Fixtures (the tests/apply_e2e.rs construction) ─────────────

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

/// Three packages, mirroring `apply_e2e::build_repo`: `archlinux/alpha`
/// (binary + library + a packaged `sshd.service` unit + a Debian libc6 spoof),
/// `archlinux/beta` (depends on alpha) and `debian/gamma` (multi-origin tree).
///
/// Every ref is pre-published, so an apply's fetch step never touches a
/// mirror.
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

/// The declarative config the apply RPC is pointed at (same shape as
/// `apply_e2e::write_config`: `native_pm = "debian"`, declared `sshd`).
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

// ─── Server harness ─────────────────────────────────────────────

/// Spawn `rpc::serve` on a detached OS thread — the real `instanz serve` path,
/// including its explicit multi-thread runtime construction and the CAS open.
fn spawn_serve(repository: PathBuf, rootfs: PathBuf, socket: PathBuf) {
    thread::spawn(move || {
        let config = InstanzConfig {
            rootfs: Some(rootfs),
            boot_root: None,
            bls_dir: None,
            forge_scratch: std::env::temp_dir(),
            backend: None,
            system_config: None,
            allow_privileged: false,
        };
        rpc::serve(&repository, HashAlgorithm::Blake3, &socket, config)
            .expect("serve loop failed");
    });
}

/// Wait (bounded) until the control socket file exists.
fn wait_for_socket(socket: &Path) {
    for _ in 0..500 {
        if socket.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("control socket {} never appeared", socket.display());
}

/// Connect a generated client through a `unix://` Endpoint, tolerating the
/// tick between socket-file creation and the accept loop start.
async fn connect(socket: &Path) -> InstanzServiceClient<tonic::transport::Channel> {
    let endpoint =
        Endpoint::from_shared(format!("unix://{}", socket.display())).expect("unix endpoint");
    for _ in 0..250 {
        match endpoint.connect().await {
            Ok(channel) => return InstanzServiceClient::new(channel),
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
    panic!("could not connect to {}", socket.display());
}

// ─── RPC round-trips over UDS ───────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn apply_generations_and_rollback_round_trip_over_uds() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let repository = tmp.path().join("repository");
    build_repo(&repository);
    let rootfs = tmp.path().join("system");
    let socket = tmp.path().join("instanz.sock");
    spawn_serve(repository, rootfs.clone(), socket.clone());
    wait_for_socket(&socket);
    let mut client = connect(&socket).await;

    // ── Socket hygiene (ARCHITECTURE §15): mode 0660 ────────────────────────
    // Group wiring (`extos-admin`) is PLAN 8.1.5 and deliberately not
    // asserted here.
    let mode = fs::metadata(&socket).expect("socket stat").permissions().mode() & 0o777;
    assert_eq!(mode, 0o660, "control socket mode");

    // ── Apply #1: the full 11-step pipeline, summarized on the wire ─────────
    let config = write_config(tmp.path()).display().to_string();
    let report = client
        .apply(ApplyRequest { config_path: config.clone() })
        .await
        .expect("apply rpc")
        .into_inner();
    assert!(report.error.is_none(), "apply #1 failed: {:?}", report.error);
    assert_eq!(report.generation, 1);
    assert_eq!(report.root, rootfs.join("gen-1").display().to_string());
    assert!(report.plan_ops > 0, "weave plan operations");
    assert!(report.phantom_rows > 0, "canonical + spoofed phantom rows");
    assert_eq!(
        report.lockfile,
        rootfs.join("gen-1/.lock").display().to_string()
    );
    // No boot root configured (server-side knob): the forge phase records
    // `n/a` and writes no BLS entries.
    assert_eq!(report.forge, "n/a");
    assert_eq!(report.bls_entries, 0);
    assert!(report.reaped.is_empty(), "no orphan generations");
    // PLAN 7.2.2: the declared `sshd` service is enabled by step 6.
    assert_eq!(report.services_enabled, 1);
    assert_eq!(report.services_disabled, 0);
    // The fixture declares no security: the flattened report stays empty.
    assert!(report.apparmor_profiles.is_empty());
    assert!(report.apparmor_skipped.is_empty());
    assert_eq!(report.selinux_applied, 0);
    assert!(report.selinux_skipped.is_empty());

    // The woven tree is real (apply_e2e assertions, server-driven).
    let tree = rootfs.join("gen-1");
    assert_eq!(
        fs::read_to_string(tree.join("usr/share/gamma/data")).unwrap(),
        "gamma-db\n"
    );
    assert_eq!(fs::read_link(rootfs.join("current")).unwrap(), Path::new("gen-1"));
    let dpkg_status = fs::read_to_string(tree.join("var/lib/dpkg/status")).unwrap();
    assert!(dpkg_status.contains("Package: libc6"), "spoofed row woven");

    // ── Generations: the tracker row, current marker and lockfile packages ──
    let gens = client
        .generations(GenerationsRequest {})
        .await
        .expect("generations rpc")
        .into_inner();
    assert!(gens.error.is_none(), "{:?}", gens.error);
    assert_eq!(gens.generations.len(), 1);
    let row = &gens.generations[0];
    assert_eq!(row.number, 1);
    assert!(row.is_current, "gen-1 is current");
    assert_eq!(row.packages.len(), 3, "lockfile packages: {:?}", row.packages);
    assert!(
        row.packages.iter().any(|p| p == "archlinux/alpha"),
        "{:?}",
        row.packages
    );
    assert!(row.timestamp.is_some(), "tracker timestamp recorded");
    assert!(row.description.contains("instanz apply"), "{:?}", row.description);
    assert!(!row.pinned);

    // ── Apply #2: a second generation on the same root ──────────────────────
    let report2 = client
        .apply(ApplyRequest { config_path: config.clone() })
        .await
        .expect("apply rpc")
        .into_inner();
    assert!(report2.error.is_none(), "apply #2 failed: {:?}", report2.error);
    assert_eq!(report2.generation, 2);
    assert_eq!(fs::read_link(rootfs.join("current")).unwrap(), Path::new("gen-2"));

    // ── Rollback: the oneof `previous` target moves `current` back ──────────
    let rolled = client
        .rollback(RollbackRequest {
            target: Some(rollback_request::Target::Previous(PreviousGeneration {})),
        })
        .await
        .expect("rollback rpc")
        .into_inner();
    assert!(rolled.error.is_none(), "{:?}", rolled.error);
    assert_eq!(rolled.generation, 1);
    assert_eq!(rolled.root, rootfs.join("gen-1").display().to_string());
    assert_eq!(fs::read_link(rootfs.join("current")).unwrap(), Path::new("gen-1"));

    // ── Container: an isolated-level launch of a profile without a program ──
    // The fixture declares no `containerPermissions`, and the RPC carries no
    // program field — `run.rs` refuses with the CLI's typed "no container
    // program" error after really resolving the roof and projection. A real
    // launch needs a launchable profile; this pins the honest refusal.
    let run = client
        .container(ContainerRequest {
            profile: "alpha".into(),
            level: Some(IsolationLevel::Isolated as i32),
        })
        .await
        .expect("container rpc (transport stays OK)")
        .into_inner();
    let err = run.error.expect("a profile without a program is a domain error");
    assert_eq!(err.code, ErrorCode::Internal as i32, "{err:?}");
    assert!(err.message.contains("no container program"), "{err:?}");
    assert!(run.roof.is_empty(), "no roof was reported for a failed run");
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_root_lists_no_generations_and_rollback_is_a_typed_error() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let repository = tmp.path().join("repository");
    let rootfs = tmp.path().join("system");
    let socket = tmp.path().join("instanz.sock");
    spawn_serve(repository, rootfs.clone(), socket.clone());
    wait_for_socket(&socket);
    let mut client = connect(&socket).await;

    // A fresh generations root is an empty success (`SnapshotEngine::open`
    // creates it exactly like the CLI) — not an error.
    let gens = client
        .generations(GenerationsRequest {})
        .await
        .expect("generations rpc")
        .into_inner();
    assert!(gens.error.is_none(), "{:?}", gens.error);
    assert!(gens.generations.is_empty());

    // Rollback without any generation is the typed orchestration error,
    // riding the response with gRPC status OK.
    let rolled = client
        .rollback(RollbackRequest { target: None })
        .await
        .expect("rollback rpc (transport stays OK)")
        .into_inner();
    let err = rolled.error.expect("no generations is a domain error");
    assert_eq!(err.code, ErrorCode::Internal as i32, "{err:?}");
    assert!(
        err.message.contains("no generations under"),
        "{err:?}"
    );
    assert_eq!(rolled.generation, 0);
    assert!(rolled.root.is_empty());
    assert!(rootfs.is_dir(), "the rootfs root was created by the listing");
}

#[tokio::test(flavor = "multi_thread")]
async fn container_on_a_never_applied_rootfs_is_a_typed_error() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let repository = tmp.path().join("repository");
    let rootfs = tmp.path().join("absent-system");
    let socket = tmp.path().join("instanz.sock");
    spawn_serve(repository, rootfs.clone(), socket.clone());
    wait_for_socket(&socket);
    let mut client = connect(&socket).await;

    // The rootfs was never applied: `run.rs`'s `resolve_roof` refuses with
    // the CLI's typed "run requires an applied system" error before any
    // container machinery runs.
    let run = client
        .container(ContainerRequest {
            profile: "alpha".into(),
            level: Some(IsolationLevel::Isolated as i32),
        })
        .await
        .expect("container rpc (transport stays OK)")
        .into_inner();
    let err = run.error.expect("a never-applied rootfs is a domain error");
    assert_eq!(err.code, ErrorCode::Internal as i32, "{err:?}");
    assert!(
        err.message.contains("run requires an applied system"),
        "{err:?}"
    );
    assert!(!rootfs.exists(), "run never invents a rootfs");
}

#[test]
fn serve_reports_taken_socket_as_typed_bind_error() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let socket = tmp.path().join("taken.sock");
    // Hold the path with a plain std listener: a second bind must fail typed,
    // naming the socket path (the operator-facing `instanz serve` behaviour).
    let _held = std::os::unix::net::UnixListener::bind(&socket).expect("hold socket");
    match rpc::bind_control_socket(&socket) {
        Err(ServeError::Bind { path, .. }) => assert_eq!(path, socket),
        other => panic!("expected ServeError::Bind, got {other:?}"),
    }
}
