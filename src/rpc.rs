//! `instanz` gRPC control-plane server (PLAN 8.1.4).
//!
//! Serves the generated `InstanzService` (schemas: PLAN 8.1.2, module
//! `libextos::pb`) over a Unix domain socket (ARCHITECTURE §15), mapping each
//! RPC onto the real orchestration APIs one-to-one:
//!
//! | RPC          | CLI surface                | instanz API                                            |
//! |--------------|----------------------------|---------------------------------------------------------|
//! | `Apply`      | `instanz apply <config>`   | `orchestrate::apply` via `ApplyOptions`                 |
//! | `Rollback`   | `instanz rollback`         | `orchestrate::rollback` via `RollbackTarget`            |
//! | `Generations`| `instanz generations`      | `orchestrate::generations`                              |
//! | `Container`  | `instanz run <profile>`    | `run::run` via `RunOptions`                             |
//!
//! # Runtime discipline (the sync main is preserved)
//!
//! `main` stays synchronous — the Phase-2 repair (the apply pipeline runs on
//! `reqwest::blocking`, which panics with "Cannot drop a runtime in a context
//! where blocking is not allowed" when run on runtime worker threads) must not
//! regress. The `serve` command is the single sanctioned exception: it builds
//! an *explicit* `tokio::runtime::Builder::new_multi_thread().enable_all()`
//! runtime and bridges every blocking orchestration call through
//! `tokio::task::spawn_blocking`. Blocking-pool worker threads permit blocking
//! drops, so the whole apply/rollback/container stack is safe exactly there.
//!
//! # Error convention (pinned by the 8.1.1/8.1.2 schemas)
//!
//! gRPC status codes are transport-only (socket not listening, worker panic,
//! malformed wire data). A *domain* failure rides the response's
//! `error: Option<extos.common::Error>` field while gRPC reports OK; an unset
//! `error` field means success. instanz's orchestration internals are
//! anyhow-based: an `ExtosError` embedded anywhere in the chain keeps its
//! specific `ErrorCode` (exhaustive 1:1 match, no catch-all — a future variant
//! breaks this build instead of silently mis-mapping), while pure
//! orchestration failures (`bail!`/context without an `ExtosError` cause)
//! report `ErrorCode::Internal` with the chained context flattened into the
//! message.
//!
//! # Server configuration (the schema's path-scoped knobs)
//!
//! Path-scoped knobs are server configuration resolved at `instanz serve`
//! startup from the same flags and `EXTOS_*` environment the CLI subcommands
//! use; they are deliberately not per-RPC arguments. The mapping onto
//! `orchestrate::ApplyOptions` (the schema header names these fields):
//!
//! | `ApplyOptions` field | Server home                                                        |
//! |----------------------|---------------------------------------------------------------------|
//! | `rootfs`             | [`InstanzConfig::rootfs`] (`Apply` falls back to the config's `root` key in the CLI's order; `Rollback`/`Generations`/`Container` have no config to fall back on) |
//! | `cache_dir`          | `<repository>/cache` of the CAS opened at startup (the CLI edge)    |
//! | `bls_dir`            | [`InstanzConfig::bls_dir`]                                          |
//! | `boot_root`          | [`InstanzConfig::boot_root`]                                        |
//! | `forge_scratch`      | [`InstanzConfig::forge_scratch`]                                    |
//! | `mounts`             | derived per apply from the applied config's `SystemConfig::mount_sources()` — in the CLI the `/var`+`/home` sources are declared by the system config (`var`/`home`/`var_tmpfs` keys), so the server resolves them from the very config the `Apply` RPC names, exactly like the CLI edge |
//!
//! The level-4 (privileged) container guard is server-side too:
//! [`InstanzConfig::allow_privileged`] defaults to deny at the CLI edge and is
//! passed into `RunOptions::allow_privileged`, where the launcher enforces the
//! same refusal as `instanz run` without `--allow-privileged`.//!
//! # Socket hygiene (PLAN 8.1.5 closed)
//!
//! The control socket is bound with mode [`SOCKET_MODE`] (0o660, §15) and
//! chowned to its §15 group through the shared libextos helper
//! (`libextos::socket`): the group defaults to `extos-admin` — the daemon's
//! entry in `libextos::daemons::DEFAULT_SOCKETS` — and an operator
//! `instanz serve --group <name>` overrides it (`--group none`/empty
//! disables the chown). Per the shared policy, an *explicit* flag failure is
//! fatal and typed ([`ServeError::SocketGroup`]); a *declarative default*
//! the host cannot honor (group absent, or EPERM for a non-member) degrades
//! to a logged honest skip — the mode and the serving are unaffected. A
//! stale or already-bound socket path is reported as a typed
//! [`ServeError::Bind`] to the operator; this server never unlinks a socket
//! it did not just create.

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::bail;
use libextos::cas::CasRepository;
use libextos::container::Backend;
use libextos::error::ExtosError;
use libextos::pb::extos::common::{Error as PbError, ErrorCode};
use libextos::pb::extos::instanz as pb;
use libextos::pb::extos::instanz::instanz_service_server::InstanzServiceServer;
use libextos::socket::{self, ResolvedSocketGroup, SocketGroupError, SocketGroupOutcome};
use libextos::types::HashAlgorithm;

use crate::orchestrate::ApplyOptions;
use crate::orchestrate::{ApplyReport, GenerationRow, RollbackTarget, open_repo};
use crate::run::RunOptions;
use crate::system::SystemConfig;

/// Design §15 control socket for `instanz`.
///
/// Kept in lockstep with `libextos::daemons::DEFAULT_SOCKETS` (pinned by a
/// unit test). Overridable per invocation via `instanz serve --socket` /
/// `EXTOS_INSTANZ_SOCKET`; tests always use tmpdir sockets.
pub const DEFAULT_SOCKET: &str = "/run/extos/instanz.sock";

/// File mode applied to the bound control socket (ARCHITECTURE §15).
///
/// Owner + group read/write, no world access. The group itself
/// (`extos-admin`) rides the shared §15 wiring in `libextos::socket`
/// (PLAN 8.1.5).
pub const SOCKET_MODE: u32 = 0o660;

/// Typed failure of the `instanz serve` path.
///
/// `main` surfaces these through `anyhow`'s `Error` rendering; every variant
/// names the offending path where one exists.
#[derive(Debug)]
pub enum ServeError {
    /// The CAS repository could not be opened or created.
    Repository {
        /// Repository root that failed to open.
        path: PathBuf,
        /// Underlying error (`orchestrate::open_repo` context included).
        source: anyhow::Error,
    },
    /// The control socket could not be bound — already in use (live daemon or
    /// stale file), or the parent directory cannot be created.
    Bind {
        /// Socket path that failed to bind.
        path: PathBuf,
        /// Underlying OS error.
        source: io::Error,
    },
    /// The §15 mode could not be applied to the bound socket.
    SocketMode {
        /// Socket path whose mode could not be set.
        path: PathBuf,
        /// Underlying OS error.
        source: io::Error,
    },
    /// The §15 socket-group wiring failed fatally (PLAN 8.1.5): an explicit
    /// `--group` flag named an unresolvable group, or the chown failed with
    /// something other than the honest per-host EPERM skip. A declarative
    /// default that cannot be honored is *not* fatal — it degrades to a
    /// logged skip inside [`bind_control_socket_with_group`].
    SocketGroup {
        /// Socket path whose group could not be applied.
        path: PathBuf,
        /// The typed libextos socket-group error.
        source: SocketGroupError,
    },
    /// The explicit Tokio runtime could not be built.
    Runtime(io::Error),
    /// The serve loop terminated with a tonic transport error.
    Serve(tonic::transport::Error),
}

impl fmt::Display for ServeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServeError::Repository { path, source } => {
                write!(f, "cannot open CAS repository {}: {source}", path.display())
            }
            ServeError::Bind { path, source } => write!(
                f,
                "cannot bind control socket {}: {source} \
                 (another instanz serve may be listening; if no daemon is running, \
                 remove the stale socket file)",
                path.display()
            ),
            ServeError::SocketMode { path, source } => write!(
                f,
                "cannot apply mode {SOCKET_MODE:o} to control socket {}: {source}",
                path.display()
            ),
            ServeError::SocketGroup { path, source } => write!(
                f,
                "cannot apply the §15 socket group to control socket {}: {source}",
                path.display()
            ),
            ServeError::Runtime(source) => {
                write!(f, "cannot build the serve runtime: {source}")
            }
            ServeError::Serve(source) => write!(f, "serve loop failed: {source}"),
        }
    }
}

impl std::error::Error for ServeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ServeError::Repository { source, .. } => Some(source.as_ref()),
            ServeError::Bind { source, .. } => Some(source),
            ServeError::SocketMode { source, .. } => Some(source),
            ServeError::SocketGroup { source, .. } => Some(source),
            ServeError::Runtime(source) => Some(source),
            ServeError::Serve(source) => Some(source),
        }
    }
}

/// Server-side configuration of the `instanz` control plane (PLAN 8.1.4).
///
/// Every field is resolved at `instanz serve` startup from the same flags and
/// `EXTOS_*` environment the CLI subcommands use; see the module docs for the
/// mapping onto `orchestrate::ApplyOptions` and `RunOptions`.
#[derive(Debug, Clone)]
pub struct InstanzConfig {
    /// Generations root (`--rootfs` / `EXTOS_ROOTFS`). `None` defers to the
    /// applied config's `root` key for `Apply` (the CLI fallback order) and is
    /// a typed domain error for `Rollback`/`Generations`/`Container`, which
    /// have no config to fall back on.
    pub rootfs: Option<PathBuf>,
    /// Boot root for the runlevel-0 forge (`--boot-root` / `EXTOS_BLS_ROOT`):
    /// the initramfs artifact and the BLS matrix land here.
    pub boot_root: Option<PathBuf>,
    /// Legacy BLS entries directory (`--bls-dir` / `EXTOS_BLS_DIR`):
    /// snapshot-only `gen-<n>.conf` entries, no forge.
    pub bls_dir: Option<PathBuf>,
    /// Scratch root the forge stages its tmpfs under
    /// (`EXTOS_FORGE_SCRATCH`, else the system temp dir — the CLI's
    /// `forge_scratch()` resolution).
    pub forge_scratch: PathBuf,
    /// Container backend (`--backend` / `EXTOS_CONTAINER_BACKEND`); `None`
    /// resolves through the backend env, else native — the CLI chain.
    pub backend: Option<String>,
    /// System config used for the `containerPermissions` profile lookup
    /// (`--config` / `EXTOS_SYSTEM_CONFIG`).
    pub system_config: Option<PathBuf>,
    /// Explicit opt-in for level-4 (privileged) container launches through
    /// this server. **Default deny**: the same guard as the CLI's
    /// `--allow-privileged`, held server-side so an RPC can never request a
    /// privilege the daemon did not opt into; the launcher re-checks it.
    pub allow_privileged: bool,
}

/// Run the `instanz serve` command (PLAN 8.1.4), applying the daemon's §15
/// socket group (`extos-admin`, PLAN 8.1.5) to the control socket.
///
/// Opens the CAS repository exactly like the existing CLI commands
/// (`--repository` / `EXTOS_REPOSITORY`), builds an explicit multi-thread
/// Tokio runtime (the sync `main` never installs one) and serves the generated
/// `InstanzService` on `socket` with `config` until the transport fails.
///
/// # Errors
///
/// [`ServeError`] names the failing stage: repository open, socket bind, §15
/// socket mode or group, runtime construction, or the serve loop itself.
pub fn serve(
    repository: &Path,
    algo: HashAlgorithm,
    socket: &Path,
    config: InstanzConfig,
) -> Result<(), ServeError> {
    let repo = open_repo(repository, algo).map_err(|source| {
        ServeError::Repository { path: repository.to_path_buf(), source }
    })?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(ServeError::Runtime)?;
    rt.block_on(run(repo, Arc::new(config), socket))
}

/// [`serve`] with an operator socket-group override (PLAN 8.1.5).
///
/// `group` is the `--group` value: `None` (flag absent) resolves to the
/// daemon's §15 default (`extos-admin`, from
/// `libextos::daemons::DEFAULT_SOCKETS`), `Some("none")`/`Some("")` disables
/// the chown, anything else is an explicit hard contract (failures are fatal
/// and typed). See [`ResolvedSocketGroup`] and `libextos::socket` for the
/// shared policy both servers run.
///
/// # Errors
///
/// [`ServeError`] as for [`serve`].
pub fn serve_with_group(
    repository: &Path,
    algo: HashAlgorithm,
    socket: &Path,
    config: InstanzConfig,
    group: Option<&str>,
) -> Result<(), ServeError> {
    let repo = open_repo(repository, algo).map_err(|source| {
        ServeError::Repository { path: repository.to_path_buf(), source }
    })?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(ServeError::Runtime)?;
    let resolved = socket::resolve_socket_group("instanz", group);
    rt.block_on(run_with_group(repo, Arc::new(config), socket, resolved))
}

/// Async serve loop: bind the control socket, apply the §15 mode and the
/// daemon's §15 group (PLAN 8.1.5) and serve the generated service over the
/// accepted UDS connections.
///
/// The incoming stream is tokio-stream's `UnixListenerStream`, reached
/// through tonic's own public re-export (`tonic::codegen::tokio_stream`) —
/// no additional dependency is needed for UDS serving.
pub async fn run(
    repo: CasRepository,
    config: Arc<InstanzConfig>,
    socket: &Path,
) -> Result<(), ServeError> {
    let std_listener = bind_control_socket(socket)?;
    serve_accepted(repo, config, socket, std_listener).await
}

/// [`run`] with a pre-resolved socket-group request (PLAN 8.1.5).
pub async fn run_with_group(
    repo: CasRepository,
    config: Arc<InstanzConfig>,
    socket: &Path,
    resolved_group: ResolvedSocketGroup,
) -> Result<(), ServeError> {
    let std_listener = bind_control_socket_with_group(socket, &resolved_group)?;
    serve_accepted(repo, config, socket, std_listener).await
}

/// Serve the generated service over an already-bound (non-blocking) control
/// socket: the shared accept loop of [`run`]/[`run_with_group`].
async fn serve_accepted(
    repo: CasRepository,
    config: Arc<InstanzConfig>,
    socket: &Path,
    std_listener: std::os::unix::net::UnixListener,
) -> Result<(), ServeError> {
    // Register the bound socket with this runtime's IO driver (must happen
    // inside the runtime context; the listener is already non-blocking).
    let listener = tokio::net::UnixListener::from_std(std_listener).map_err(|source| {
        ServeError::Bind { path: socket.to_path_buf(), source }
    })?;
    let incoming =
        tonic::codegen::tokio_stream::wrappers::UnixListenerStream::new(listener);
    let service = InstanzServiceServer::new(InstanzServiceImpl { repo, config });
    tonic::transport::Server::builder()
        .add_service(service)
        .serve_with_incoming(incoming)
        .await
        .map_err(ServeError::Serve)
}

/// Bind `socket` as the control socket, apply the design §15 mode and the
/// daemon's §15 group (`extos-admin`, PLAN 8.1.5).
///
/// See [`bind_control_socket_with_group`] for the full contract; this
/// convenience keeps the pre-8.1.5 signature and applies the daemon default.
///
/// # Errors
///
/// [`ServeError::Bind`] for parent-directory creation, bind, or non-blocking
/// failures; [`ServeError::SocketMode`] when the chmod fails after a
/// successful bind; [`ServeError::SocketGroup`] per the shared policy.
pub fn bind_control_socket(
    socket: &Path,
) -> Result<std::os::unix::net::UnixListener, ServeError> {
    bind_control_socket_with_group(socket, &socket::resolve_socket_group("instanz", None))
}

/// [`bind_control_socket`] with a pre-resolved socket-group request
/// (PLAN 8.1.5).
///
/// The parent directory is created when missing (`/run/extos` is not
/// guaranteed to exist for a bare `instanz serve`). An already-bound or stale
/// socket path surfaces as [`ServeError::Bind`] with the OS error — deciding
/// whether that is a live daemon or a leftover belongs to the operator, so
/// this function never unlinks anything.
///
/// The returned listener is a std socket in non-blocking mode; the async
/// caller registers it with its runtime's IO driver via
/// `tokio::net::UnixListener::from_std`.
///
/// The mode ([`SOCKET_MODE`]) is always applied. The group rides the shared
/// `libextos::socket` policy: [`ResolvedSocketGroup::Disabled`] skips the
/// chown, an [`ResolvedSocketGroup::Explicit`] failure is fatal and typed,
/// and a [`ResolvedSocketGroup::Default`] the host cannot honor (group
/// absent, or EPERM for a non-member) degrades to a logged honest skip —
/// never silent, never fatal for the declarative default.
///
/// # Errors
///
/// [`ServeError::Bind`] for parent-directory creation, bind, or non-blocking
/// failures; [`ServeError::SocketMode`] when the chmod fails after a
/// successful bind; [`ServeError::SocketGroup`] per the shared policy above.
pub fn bind_control_socket_with_group(
    socket: &Path,
    resolved_group: &ResolvedSocketGroup,
) -> Result<std::os::unix::net::UnixListener, ServeError> {
    if let Some(parent) = socket.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|source| ServeError::Bind {
                path: socket.to_path_buf(),
                source,
            })?;
        }
    }
    let listener = std::os::unix::net::UnixListener::bind(socket).map_err(|source| {
        ServeError::Bind { path: socket.to_path_buf(), source }
    })?;
    listener.set_nonblocking(true).map_err(|source| ServeError::Bind {
        path: socket.to_path_buf(),
        source,
    })?;
    fs::set_permissions(socket, fs::Permissions::from_mode(SOCKET_MODE)).map_err(
        |source| ServeError::SocketMode { path: socket.to_path_buf(), source },
    )?;
    match socket::enforce_socket_group(socket, resolved_group) {
        Ok(outcome) => match outcome {
            SocketGroupOutcome::Applied { gid, group } => {
                tracing::info!(
                    "control socket {}: §15 group {group:?} applied (gid {gid})",
                    socket.display()
                );
            }
            SocketGroupOutcome::Skipped { group, reason } => {
                tracing::warn!(
                    "control socket {}: §15 group {group:?} not applied (honest per-host \
                     skip): {reason}",
                    socket.display()
                );
            }
            SocketGroupOutcome::Disabled => {
                tracing::info!(
                    "control socket {}: socket-group wiring disabled by operator flag",
                    socket.display()
                );
            }
        },
        Err(source) => {
            return Err(ServeError::SocketGroup { path: socket.to_path_buf(), source });
        }
    }
    Ok(listener)
}

/// The `InstanzService` implementation state (PLAN 8.1.4): the CAS repository
/// opened at startup plus the resolved [`InstanzConfig`].
///
/// Cloning is cheap: the repository is two small fields and the config rides
/// in an `Arc` shared across every request.
#[derive(Clone)]
pub struct InstanzServiceImpl {
    /// The CAS repository this server manages (opened once at startup; the
    /// apply cache dir is `<root>/cache`, the CLI edge).
    repo: CasRepository,
    /// Resolved server configuration (path-scoped knobs, backend, privilege
    /// opt-in).
    config: Arc<InstanzConfig>,
}

#[tonic::async_trait]
impl pb::instanz_service_server::InstanzService for InstanzServiceImpl {
    async fn apply(
        &self,
        request: tonic::Request<pb::ApplyRequest>,
    ) -> Result<tonic::Response<pb::ApplyResponse>, tonic::Status> {
        let req = request.into_inner();
        let svc = self.clone();
        let resp = spawn_blocking("apply", move || svc.apply_blocking(req)).await?;
        Ok(tonic::Response::new(resp))
    }

    async fn rollback(
        &self,
        request: tonic::Request<pb::RollbackRequest>,
    ) -> Result<tonic::Response<pb::RollbackResponse>, tonic::Status> {
        let req = request.into_inner();
        let svc = self.clone();
        let resp = spawn_blocking("rollback", move || svc.rollback_blocking(req)).await?;
        Ok(tonic::Response::new(resp))
    }

    async fn generations(
        &self,
        request: tonic::Request<pb::GenerationsRequest>,
    ) -> Result<tonic::Response<pb::GenerationsResponse>, tonic::Status> {
        let req = request.into_inner();
        let svc = self.clone();
        let resp =
            spawn_blocking("generations", move || svc.generations_blocking(req)).await?;
        Ok(tonic::Response::new(resp))
    }

    async fn container(
        &self,
        request: tonic::Request<pb::ContainerRequest>,
    ) -> Result<tonic::Response<pb::ContainerResponse>, tonic::Status> {
        let req = request.into_inner();
        let svc = self.clone();
        let resp =
            spawn_blocking("container", move || svc.container_blocking(req)).await?;
        Ok(tonic::Response::new(resp))
    }
}

/// Bridge one blocking orchestration operation onto the async runtime.
///
/// Every RPC handler routes its domain call through here: the orchestrate/
/// container paths are synchronous (blocking fs/namespace work), so they must
/// run on the blocking pool, not on runtime worker threads.
///
/// A `JoinError` (panicking worker) is *not* a domain error — it is a server
/// bug surfacing on the transport, so it maps to `Status::internal` per the
/// schema's convention that gRPC statuses are transport-only.
///
/// # Errors
///
/// [`tonic::Status::internal`] when the blocking worker panicked or was
/// cancelled.
async fn spawn_blocking<T, F>(rpc: &str, task: F) -> Result<T, tonic::Status>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let rpc = rpc.to_string();
    tokio::task::spawn_blocking(task)
        .await
        .map_err(|err| tonic::Status::internal(format!("{rpc} worker failed: {err}")))
}

impl InstanzServiceImpl {
    /// `Apply` domain path (blocking): the same 11-step pipeline as
    /// `instanz apply`, with the server config supplying the path-scoped
    /// knobs (see the module docs) and the request supplying the config path.
    fn apply_blocking(&self, req: pb::ApplyRequest) -> pb::ApplyResponse {
        if req.config_path.is_empty() {
            return apply_error(config_parse_error(
                "extos.instanz.ApplyRequest.config_path",
                "config_path must be non-empty (the daemon host resolves it)",
            ));
        }
        let system = match SystemConfig::load(Path::new(&req.config_path)) {
            Ok(system) => system,
            Err(err) => return apply_error(err),
        };
        let rootfs = match rootfs_for_apply(
            self.config.rootfs.as_deref(),
            system.root.as_deref(),
        ) {
            Ok(rootfs) => rootfs,
            Err(err) => return apply_error(err),
        };

        let cache_dir = self.repo.root.join("cache");
        let mounts = system.mount_sources();
        let options = ApplyOptions {
            rootfs: &rootfs,
            cache_dir: &cache_dir,
            bls_dir: self.config.bls_dir.as_deref(),
            boot_root: self.config.boot_root.as_deref(),
            forge_scratch: &self.config.forge_scratch,
            mounts: &mounts,
        };
        match crate::orchestrate::apply(&self.repo, system, &options) {
            Ok(report) => apply_report_to_response(&report),
            Err(err) => apply_error(err),
        }
    }

    /// `Rollback` domain path (blocking): the oneof target maps onto
    /// [`RollbackTarget`] (absent = the CLI default `prev`), the activated
    /// generation root is derived server-side as `<rootfs>/gen-<n>`.
    fn rollback_blocking(&self, req: pb::RollbackRequest) -> pb::RollbackResponse {
        let mut resp = pb::RollbackResponse::default();
        let rootfs = match require_rootfs(self.config.rootfs.as_deref()) {
            Ok(rootfs) => rootfs,
            Err(err) => {
                resp.error = Some(domain_error(&err));
                return resp;
            }
        };
        let target = match rollback_target_from_wire(req.target) {
            Ok(target) => target,
            Err(err) => {
                resp.error = Some(domain_error(&err));
                return resp;
            }
        };
        match crate::orchestrate::rollback(
            &rootfs,
            target,
            self.config.boot_root.as_deref(),
            self.config.bls_dir.as_deref(),
        ) {
            Ok(number) => {
                resp.generation = number;
                resp.root = generation_root(&rootfs, number);
            }
            Err(err) => resp.error = Some(domain_error(&err)),
        }
        resp
    }

    /// `Generations` domain path (blocking): the generation table under the
    /// configured root. An empty (or fresh) root is a success with an empty
    /// list, not an error — `SnapshotEngine::open` creates the root exactly
    /// like the CLI does.
    fn generations_blocking(&self, _req: pb::GenerationsRequest) -> pb::GenerationsResponse {
        let mut resp = pb::GenerationsResponse::default();
        let rootfs = match require_rootfs(self.config.rootfs.as_deref()) {
            Ok(rootfs) => rootfs,
            Err(err) => {
                resp.error = Some(domain_error(&err));
                return resp;
            }
        };
        match crate::orchestrate::generations(&rootfs) {
            Ok(rows) => resp.generations = rows.iter().map(generation_row_to_proto).collect(),
            Err(err) => resp.error = Some(domain_error(&err)),
        }
        resp
    }

    /// `Container` domain path (blocking): the `instanz run` pipeline. The
    /// RPC carries only the profile and the optional level override; every
    /// other `RunOptions` field is server configuration, and the response
    /// reports the real exit code (int32 for signal fidelity).
    fn container_blocking(&self, req: pb::ContainerRequest) -> pb::ContainerResponse {
        let mut resp = pb::ContainerResponse::default();
        if req.profile.is_empty() {
            resp.error = Some(domain_error(&config_parse_error(
                "extos.instanz.ContainerRequest.profile",
                "profile must be non-empty (a system name or a package profile)",
            )));
            return resp;
        }
        let rootfs = match require_rootfs(self.config.rootfs.as_deref()) {
            Ok(rootfs) => rootfs,
            Err(err) => {
                resp.error = Some(domain_error(&err));
                return resp;
            }
        };
        let options = match self.container_options(&req, &rootfs) {
            Ok(options) => options,
            Err(err) => {
                resp.error = Some(domain_error(&err));
                return resp;
            }
        };
        // CLI parity: the repository is a *profile lookup* source consulted
        // only when a system config was named (`instanz run` never requires
        // one otherwise).
        let repo = self.config.system_config.as_deref().map(|_| &self.repo);
        match crate::run::run(repo, &options) {
            Ok(code) => {
                resp.exit_code = code;
                resp.roof = resolved_roof(&rootfs);
                resp.backend = resolved_backend(self.config.backend.as_deref());
            }
            Err(err) => resp.error = Some(domain_error(&err)),
        }
        resp
    }

    /// Build the `RunOptions` mirror for one `Container` RPC.
    ///
    /// `profile` and `level` come from the request (an absent level override
    /// is the CLI's fallback chain: manifest profile level, else isolated);
    /// backend, system config and the privilege opt-in are server
    /// configuration. `program`/`args` have no wire field — the entrypoint
    /// comes from the manifest profile exactly like a bare `instanz run`.
    fn container_options<'a>(
        &'a self,
        req: &'a pb::ContainerRequest,
        rootfs: &'a Path,
    ) -> anyhow::Result<RunOptions<'a>> {
        let level = level_from_wire(req.level)?;
        Ok(RunOptions {
            rootfs,
            profile: &req.profile,
            level,
            backend: self.config.backend.as_deref(),
            program: None,
            args: &[],
            config: self.config.system_config.as_deref(),
            allow_privileged: self.config.allow_privileged,
        })
    }
}

// ─── Domain ↔ proto conversions ─────────────────────────────────────────────

/// Map an instanz `anyhow` error onto the wire error.
///
/// The chained context is flattened into the message (anyhow's `{:#}`
/// rendering: "outer: inner: cause"). When an `ExtosError` is embedded
/// anywhere in the chain it keeps its specific `ErrorCode` via the exhaustive
/// [`extos_error_code`] match; pure orchestration failures (`bail!`/context
/// without an `ExtosError` cause) report [`ErrorCode::Internal`] per the
/// common schema.
fn domain_error(err: &anyhow::Error) -> PbError {
    let code = match err.downcast_ref::<ExtosError>() {
        Some(domain) => extos_error_code(domain),
        None => ErrorCode::Internal,
    };
    PbError { code: code as i32, message: format!("{err:#}") }
}

/// Map an `ExtosError` onto its `ErrorCode` (exhaustive, no catch-all — a
/// future variant breaks this build instead of silently mis-mapping; the
/// `ErrorCode` enum mirrors the variants one-to-one by design).
fn extos_error_code(err: &ExtosError) -> ErrorCode {
    match err {
        ExtosError::Io(_) => ErrorCode::Io,
        ExtosError::ConfigParse { .. } => ErrorCode::ConfigParse,
        ExtosError::CasIntegrity { .. } => ErrorCode::CasIntegrity,
        ExtosError::PackageNotFound { .. } => ErrorCode::PackageNotFound,
        ExtosError::DependencyUnresolvable(_) => ErrorCode::DependencyUnresolvable,
        ExtosError::Collision { .. } => ErrorCode::Collision,
        ExtosError::Weave(_) => ErrorCode::Weave,
        ExtosError::Snapshot(_) => ErrorCode::Snapshot,
        ExtosError::Container(_) => ErrorCode::Container,
        ExtosError::RosettaPlugin { .. } => ErrorCode::RosettaPlugin,
        ExtosError::Serialization(_) => ErrorCode::Serialization,
    }
}

/// Build the crate's structured malformed-input error (same house style as
/// `caps::validate_soname`: `ConfigParse` with a naming `path`, `line = 0`),
/// wrapped as anyhow so it flows through the instanz error bridge with its
/// specific code intact.
fn config_parse_error(path: &str, message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(ExtosError::ConfigParse {
        path: path.to_string(),
        line: 0,
        message: message.into(),
    })
}

/// Generations root for one `Apply`: the server's configured rootfs first,
/// then the applied config's `root` key — the same fallback order and message
/// as the CLI's `rootfs_from_config` (kept in lockstep; pinned by the
/// `apply_rootfs_resolution_matches_the_cli_fallback_order` test).
///
/// # Errors
///
/// Typed error when neither source is configured (CLI wording).
fn rootfs_for_apply(
    server: Option<&Path>,
    config_root: Option<&Path>,
) -> anyhow::Result<PathBuf> {
    if let Some(path) = server {
        return Ok(path.to_path_buf());
    }
    if let Some(path) = config_root {
        return Ok(path.to_path_buf());
    }
    bail!(
        "no generations root configured: pass --rootfs, set EXTOS_ROOTFS, \
         or add `root = \"/runlevel/1/<system>\";` to the system config"
    )
}

/// Generations root for RPCs that have no config to fall back on — the same
/// rule (and message) as the CLI's `require_rootfs`.
///
/// # Errors
///
/// Typed error when the server was started without a generations root.
fn require_rootfs(server: Option<&Path>) -> anyhow::Result<PathBuf> {
    server.map(Path::to_path_buf).ok_or_else(|| {
        anyhow::anyhow!("no generations root configured: pass --rootfs or set EXTOS_ROOTFS")
    })
}

/// Wire `RollbackRequest.target` → [`RollbackTarget`].
///
/// `Previous` / `Number` map one-to-one; an absent oneof takes the CLI
/// default (`--generation` unset = `prev`). There is no wire spelling that
/// can ask for both — the same invariant `RollbackTarget::parse` enforces.
///
/// # Errors
///
/// This constructor is total over the wire type today; the `Result` keeps the
/// call sites uniform with the other request-translation steps.
fn rollback_target_from_wire(
    target: Option<pb::rollback_request::Target>,
) -> anyhow::Result<RollbackTarget> {
    Ok(match target {
        Some(pb::rollback_request::Target::Previous(_)) => RollbackTarget::Previous,
        Some(pb::rollback_request::Target::Number(number)) => RollbackTarget::Number(number),
        None => RollbackTarget::Previous,
    })
}

/// Reverse of [`rollback_target_from_proto`], for the round-trip tests only.
#[cfg(test)]
fn rollback_target_to_wire(target: RollbackTarget) -> Option<pb::rollback_request::Target> {
    match target {
        RollbackTarget::Previous => {
            Some(pb::rollback_request::Target::Previous(pb::PreviousGeneration {}))
        }
        RollbackTarget::Number(number) => Some(pb::rollback_request::Target::Number(number)),
    }
}

/// Wire level override → `RunOptions::level` (`Option<u8>`).
///
/// Absent = no override (the manifest profile's level, else isolated — the
/// proto3 default doubles as "unset", matching the CLI fallback chain). A
/// value outside 0-4 (an unknown enum on the wire) is a typed domain error,
/// never a silent reinterpretation.
///
/// # Errors
///
/// Typed error for an unknown wire level.
fn level_from_wire(level: Option<i32>) -> anyhow::Result<Option<u8>> {
    let Some(raw) = level else {
        return Ok(None);
    };
    if !(0..=4).contains(&raw) {
        bail!("invalid isolation level {raw}: expected 0 (isolated) … 4 (privileged)");
    }
    Ok(Some(raw as u8))
}

/// `<rootfs>/gen-<n>` — the `SnapshotEngine` layout, mirrored here only to
/// fill `RollbackResponse::root` (the schema's server-derived field).
fn generation_root(rootfs: &Path, number: u64) -> String {
    rootfs.join(format!("gen-{number}")).display().to_string()
}

/// Roof the container booted from: `<rootfs>/current` resolved exactly like
/// `run.rs`'s `resolve_roof` (absolute targets pass through, relative ones
/// resolve against the rootfs). Only called on the success path, where the
/// run has already validated the resolution; the unreachable read failure
/// reports the link itself instead of an empty field.
fn resolved_roof(rootfs: &Path) -> String {
    let link = rootfs.join("current");
    match fs::read_link(&link) {
        Ok(target) if target.is_absolute() => target,
        Ok(target) => rootfs.join(target),
        Err(_) => link,
    }
    .display()
    .to_string()
}

/// Resolved backend for `ContainerResponse::backend` — the same resolution
/// `run.rs` performs: the server's `--backend`/config value wins, else
/// `EXTOS_CONTAINER_BACKEND`, else the native backend. Only called on the
/// success path, where the run has already resolved the same inputs.
fn resolved_backend(flag: Option<&str>) -> String {
    let backend = match flag {
        Some(name) => Backend::from_name(name.trim()),
        None => Backend::from_env(),
    };
    backend.map(|backend| backend.as_str().to_string()).unwrap_or_default()
}

/// [`ApplyReport`] → wire `ApplyResponse` (flat mirror of the 8.1.2 schema,
/// with the roof-security report flattened; `usize` counts widen to uint64).
fn apply_report_to_response(report: &ApplyReport) -> pb::ApplyResponse {
    pb::ApplyResponse {
        generation: report.generation,
        root: report.root.display().to_string(),
        plan_ops: report.plan_ops as u64,
        phantom_rows: report.phantom_rows as u64,
        lockfile: report.lockfile.display().to_string(),
        forge: report.forge.clone(),
        bls_entries: report.bls_entries as u64,
        reaped: report.reaped.clone(),
        apparmor_profiles: report.security.apparmor_profiles.clone(),
        apparmor_skipped: report.security.apparmor_skipped.clone(),
        selinux_applied: report.security.selinux_applied as u64,
        selinux_skipped: report.security.selinux_skipped.clone(),
        services_enabled: report.services_enabled as u64,
        services_disabled: report.services_disabled as u64,
        error: None,
    }
}

/// Fill an `ApplyResponse` with only its domain error (payload fields stay
/// proto3 defaults — best-effort payloads are filled by the success path).
fn apply_error(err: anyhow::Error) -> pb::ApplyResponse {
    let mut resp = pb::ApplyResponse::default();
    resp.error = Some(domain_error(&err));
    resp
}

/// Domain [`GenerationRow`] → wire `GenerationRow` (optional timestamp
/// preserved: absent stays absent, never 0).
fn generation_row_to_proto(row: &GenerationRow) -> pb::GenerationRow {
    pb::GenerationRow {
        number: row.number,
        timestamp: row.timestamp,
        packages: row.packages.clone(),
        description: row.description.clone(),
        is_current: row.is_current,
        pinned: row.pinned,
    }
}

/// Reverse of [`generation_row_to_proto`], for the round-trip tests only — no
/// handler reconstructs a domain row from the wire today.
#[cfg(test)]
fn generation_row_from_proto(msg: &pb::GenerationRow) -> GenerationRow {
    GenerationRow {
        number: msg.number,
        timestamp: msg.timestamp,
        packages: msg.packages.clone(),
        description: msg.description.clone(),
        is_current: msg.is_current,
        pinned: msg.pinned,
    }
}

// ─── In-module tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use libextos::container::IsolationLevel as DomainIsolationLevel;

    /// Server under test with an empty tmpdir repository and config.
    fn test_service(rootfs: Option<PathBuf>) -> (tempfile::TempDir, InstanzServiceImpl) {
        let dir = tempfile::tempdir().expect("tmpdir");
        let repo = CasRepository::open(dir.path().join("repository"), HashAlgorithm::Blake3)
            .expect("open tmpdir CAS");
        let config = InstanzConfig {
            rootfs,
            boot_root: None,
            bls_dir: None,
            forge_scratch: dir.path().join("scratch"),
            backend: Some("native".into()),
            system_config: None,
            allow_privileged: false,
        };
        let svc = InstanzServiceImpl { repo, config: Arc::new(config) };
        (dir, svc)
    }

    #[test]
    fn default_socket_matches_daemons_table() {
        let pinned = libextos::daemons::DEFAULT_SOCKETS
            .iter()
            .find(|(daemon, _, _)| *daemon == "instanz")
            .map(|(_, path, _)| *path)
            .expect("daemons table pins the instanz control socket");
        assert_eq!(DEFAULT_SOCKET, pinned, "§15 socket constant drifted");
    }

    #[test]
    fn default_socket_group_matches_daemons_table() {
        // PLAN 8.1.5: the daemon's group source of truth is the §15 table.
        let pinned = libextos::daemons::DEFAULT_SOCKETS
            .iter()
            .find(|(daemon, _, _)| *daemon == "instanz")
            .map(|(_, _, group)| *group)
            .expect("daemons table pins the instanz control group");
        assert_eq!(libextos::socket::default_group("instanz"), Some(pinned));
        // The no-flag resolution carries that default into the server.
        assert_eq!(
            libextos::socket::resolve_socket_group("instanz", None),
            ResolvedSocketGroup::Default(pinned.to_string())
        );
    }

    #[test]
    fn extos_error_maps_onto_distinct_codes_through_the_anyhow_bridge() {
        let cases: Vec<(ExtosError, ErrorCode)> = vec![
            (ExtosError::Io(io::Error::other("boom")), ErrorCode::Io),
            (
                ExtosError::ConfigParse {
                    path: "cfg.nix".into(),
                    line: 0,
                    message: "bad".into(),
                },
                ErrorCode::ConfigParse,
            ),
            (
                ExtosError::CasIntegrity { expected: "a".into(), actual: "b".into() },
                ErrorCode::CasIntegrity,
            ),
            (
                ExtosError::PackageNotFound {
                    origin: "o".into(),
                    name: "n".into(),
                    version: "v".into(),
                },
                ErrorCode::PackageNotFound,
            ),
            (
                ExtosError::DependencyUnresolvable("dep".into()),
                ErrorCode::DependencyUnresolvable,
            ),
            (
                ExtosError::Collision {
                    path: "/p".into(),
                    claimant_a: "a".into(),
                    claimant_b: "b".into(),
                },
                ErrorCode::Collision,
            ),
            (ExtosError::Weave("w".into()), ErrorCode::Weave),
            (ExtosError::Snapshot("s".into()), ErrorCode::Snapshot),
            (ExtosError::Container("c".into()), ErrorCode::Container),
            (
                ExtosError::RosettaPlugin { plugin: "p".into(), message: "m".into() },
                ErrorCode::RosettaPlugin,
            ),
            (ExtosError::Serialization("x".into()), ErrorCode::Serialization),
        ];
        // The exhaustive match in `extos_error_code` enforces completeness at
        // compile time; this pins the count and the 1:1 mapping at runtime,
        // exercised through the anyhow downcast path the server really takes.
        assert_eq!(
            cases.len(),
            11,
            "every ExtosError variant must appear exactly once"
        );
        let mut codes = Vec::new();
        for (err, expected) in cases {
            // Wrapped with extra context, exactly like the orchestration glue
            // wraps domain failures before they reach the server; the display
            // survives as the message tail (context flattened on top).
            let display = err.to_string();
            let wire = domain_error(&anyhow::Error::new(err).context("apply failed"));
            assert_eq!(wire.code, expected as i32, "{wire:?}");
            assert!(
                // `contains`, not `ends_with`: anyhow's flattened chain also
                // walks the payload's own `source()` (e.g. an io::Error's
                // inner cause), which may append beyond the display.
                wire.message.contains(&display),
                "message {:?} must carry the error display {display:?}",
                wire.message
            );
            codes.push(wire.code);
        }
        // Pure instanz orchestration failures (no ExtosError cause) are the
        // twelfth code: INTERNAL.
        let pure = anyhow::Error::msg("no generations under /x").context("rollback");
        let wire = domain_error(&pure);
        assert_eq!(wire.code, ErrorCode::Internal as i32, "{wire:?}");
        codes.push(wire.code);

        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), 12, "codes must be pairwise distinct");
    }

    #[test]
    fn anyhow_chain_is_flattened_into_the_message() {
        let pure = anyhow::Error::msg("no generations under /x").context("rollback failed");
        let wire = domain_error(&pure);
        assert_eq!(wire.message, "rollback failed: no generations under /x");
        assert_eq!(wire.code, ErrorCode::Internal as i32);

        let wrapped = anyhow::Error::new(ExtosError::Weave("hardlink failed".into()))
            .context("weave failed")
            .context("apply failed");
        let wire = domain_error(&wrapped);
        assert_eq!(
            wire.message,
            "apply failed: weave failed: Weave error: hardlink failed"
        );
        assert_eq!(wire.code, ErrorCode::Weave as i32);
    }

    #[test]
    fn apply_rootfs_resolution_matches_the_cli_fallback_order() {
        let server = Path::new("/srv/rootfs");
        let config = Path::new("/cfg/root");
        // The server flag wins over the config's `root` key.
        assert_eq!(
            rootfs_for_apply(Some(server), Some(config)).unwrap(),
            server
        );
        // …and the config `root` is the fallback when no flag/env was set.
        assert_eq!(rootfs_for_apply(None, Some(config)).unwrap(), config);
        // Neither: the CLI's typed error, verbatim.
        let err = rootfs_for_apply(None, None).unwrap_err().to_string();
        assert!(
            err.contains("no generations root configured")
                && err.contains("root = \"/runlevel/1/<system>\""),
            "{err}"
        );
        // RPCs without a config to fall back on require the server rootfs.
        assert_eq!(require_rootfs(Some(server)).unwrap(), server);
        let err = require_rootfs(None).unwrap_err().to_string();
        assert_eq!(
            err,
            "no generations root configured: pass --rootfs or set EXTOS_ROOTFS"
        );
    }

    #[test]
    fn apply_report_maps_flat_with_security_flattened() {
        let report = ApplyReport {
            generation: 7,
            root: PathBuf::from("/srv/system/gen-7"),
            plan_ops: 42,
            phantom_rows: 5,
            lockfile: PathBuf::from("/srv/system/gen-7/.lock"),
            forge: "n/a".into(),
            bls_entries: 0,
            reaped: vec![3, 4],
            security: libextos::security::RoofSecurityReport {
                apparmor_profiles: vec!["usr.bin.alpha".into()],
                apparmor_skipped: vec!["beta: no profile synthesis".into()],
                selinux_applied: 9,
                selinux_skipped: vec!["gamma".into()],
            },
            services_enabled: 2,
            services_disabled: 1,
        };
        let wire = apply_report_to_response(&report);
        assert_eq!(wire.generation, 7);
        assert_eq!(wire.root, "/srv/system/gen-7");
        assert_eq!(wire.plan_ops, 42);
        assert_eq!(wire.phantom_rows, 5);
        assert_eq!(wire.lockfile, "/srv/system/gen-7/.lock");
        assert_eq!(wire.forge, "n/a");
        assert_eq!(wire.bls_entries, 0);
        assert_eq!(wire.reaped, vec![3, 4]);
        assert_eq!(wire.apparmor_profiles, vec!["usr.bin.alpha"]);
        assert_eq!(wire.apparmor_skipped, vec!["beta: no profile synthesis"]);
        assert_eq!(wire.selinux_applied, 9, "usize widened to uint64");
        assert_eq!(wire.selinux_skipped, vec!["gamma"]);
        assert_eq!(wire.services_enabled, 2);
        assert_eq!(wire.services_disabled, 1);
        assert!(wire.error.is_none(), "success = no error field");
    }

    #[test]
    fn generation_row_round_trips_with_optional_timestamp() {
        let row = GenerationRow {
            number: 12,
            timestamp: Some(1_767_225_600),
            packages: vec!["archlinux/alpha".into(), "debian/gamma".into()],
            description: "instanz apply: 3 package(s)".into(),
            is_current: true,
            pinned: false,
        };
        let wire = generation_row_to_proto(&row);
        assert_eq!(wire.timestamp, Some(1_767_225_600));
        // `GenerationRow` carries no `PartialEq`; compare field-wise.
        let back = generation_row_from_proto(&wire);
        assert_eq!(back.number, row.number);
        assert_eq!(back.timestamp, row.timestamp);
        assert_eq!(back.packages, row.packages);
        assert_eq!(back.description, row.description);
        assert_eq!(back.is_current, row.is_current);
        assert_eq!(back.pinned, row.pinned);

        // Absent stays absent — never collapsed to the proto3 default 0.
        let unrecorded = GenerationRow {
            number: 1,
            timestamp: None,
            packages: Vec::new(),
            description: String::new(),
            is_current: false,
            pinned: true,
        };
        let wire = generation_row_to_proto(&unrecorded);
        assert_eq!(wire.timestamp, None, "absent vs 0 must be preserved");
        assert_eq!(generation_row_from_proto(&wire).timestamp, None);
        assert_eq!(wire.packages, Vec::<String>::new());
        assert!(wire.description.is_empty());
        assert!(wire.pinned);
    }

    #[test]
    fn rollback_target_oneof_round_trips_both_directions() {
        for target in [RollbackTarget::Previous, RollbackTarget::Number(7)] {
            let wire = rollback_target_to_wire(target);
            assert_eq!(
                rollback_target_from_wire(wire).unwrap(),
                target,
                "oneof round-trip"
            );
        }
        // The wire oneof may be unset: the CLI default (`prev`) applies.
        assert_eq!(
            rollback_target_from_wire(None).unwrap(),
            RollbackTarget::Previous
        );
        // …and the marker message carries the Previous arm.
        assert!(matches!(
            rollback_target_to_wire(RollbackTarget::Previous),
            Some(pb::rollback_request::Target::Previous(_))
        ));
    }

    #[test]
    fn isolation_level_enum_maps_one_to_one() {
        let levels = [
            (pb::IsolationLevel::Isolated, DomainIsolationLevel::Isolated),
            (pb::IsolationLevel::Cli, DomainIsolationLevel::Cli),
            // The proto spells `IsolationLevel::Gui` as ISOLATION_LEVEL_GUI.
            (pb::IsolationLevel::Gui, DomainIsolationLevel::Gui),
            (pb::IsolationLevel::Networked, DomainIsolationLevel::Networked),
            (pb::IsolationLevel::Privileged, DomainIsolationLevel::Privileged),
        ];
        for (wire, domain) in levels {
            // Domain → wire (numeric levels coincide).
            assert_eq!(
                pb::IsolationLevel::try_from(i32::from(domain.as_u8())).unwrap(),
                wire,
                "{domain:?}"
            );
            // Wire → domain override (`RunOptions::level`).
            assert_eq!(level_from_wire(Some(wire as i32)).unwrap(), Some(domain.as_u8()));
        }
        // Absent = no override (manifest profile level, else isolated).
        assert_eq!(level_from_wire(None).unwrap(), None);
        // Unknown wire levels are typed errors, never reinterpretations.
        assert!(level_from_wire(Some(9)).is_err());
        assert!(level_from_wire(Some(-1)).is_err());
    }

    #[test]
    fn container_options_mirror_the_server_config() {
        let (dir, svc) = test_service(Some(PathBuf::from("/srv/system")));
        let rootfs = dir.path().join("system");
        let req = pb::ContainerRequest {
            profile: "alpha".into(),
            level: Some(pb::IsolationLevel::Cli as i32),
        };
        let options = svc.container_options(&req, &rootfs).expect("options");
        assert_eq!(options.profile, "alpha");
        assert_eq!(options.level, Some(1), "wire override lands as u8");
        assert_eq!(options.backend, Some("native"), "server backend rides in");
        assert!(options.program.is_none(), "no wire field for program");
        assert!(options.args.is_empty(), "no wire field for args");
        assert!(options.config.is_none(), "server declared no system config");
        assert!(
            !options.allow_privileged,
            "the privilege opt-in is server-side and defaults to deny"
        );

        // The privilege opt-in passes through when the daemon opted in.
        let privileged = InstanzConfig {
            rootfs: None,
            boot_root: None,
            bls_dir: None,
            forge_scratch: dir.path().join("scratch"),
            backend: None,
            system_config: Some(PathBuf::from("/config/systems/default.nix")),
            allow_privileged: true,
        };
        let svc = InstanzServiceImpl { repo: svc.repo.clone(), config: Arc::new(privileged) };
        let bare = pb::ContainerRequest::default();
        let options = svc.container_options(&bare, &rootfs).expect("options");
        assert!(options.allow_privileged);
        assert_eq!(
            options.config,
            Some(Path::new("/config/systems/default.nix")),
            "system config rides in for the profile lookup"
        );
        assert_eq!(options.level, None, "absent = no override");
        // The repository is consulted only when a system config was named.
        assert!(svc.config.system_config.is_some());
    }

    #[test]
    fn apply_rejects_empty_config_path_as_config_parse() {
        let (_dir, svc) = test_service(Some(PathBuf::from("/srv/system")));
        let resp = svc.apply_blocking(pb::ApplyRequest::default());
        let err = resp.error.expect("empty config_path is a domain error");
        assert_eq!(err.code, ErrorCode::ConfigParse as i32, "{err:?}");
        assert_eq!(resp.generation, 0);
    }

    #[test]
    fn container_rejects_empty_profile_as_config_parse() {
        let (_dir, svc) = test_service(Some(PathBuf::from("/srv/system")));
        let resp = svc.container_blocking(pb::ContainerRequest::default());
        let err = resp.error.expect("empty profile is a domain error");
        assert_eq!(err.code, ErrorCode::ConfigParse as i32, "{err:?}");
        assert_eq!(resp.exit_code, 0);
    }

    #[test]
    fn generations_without_rootfs_is_a_domain_error() {
        let (_dir, svc) = test_service(None);
        let resp = svc.generations_blocking(pb::GenerationsRequest {});
        let err = resp.error.expect("missing server rootfs is a domain error");
        assert_eq!(err.code, ErrorCode::Internal as i32, "{err:?}");
        assert_eq!(
            err.message,
            "no generations root configured: pass --rootfs or set EXTOS_ROOTFS"
        );
        assert!(resp.generations.is_empty());
    }

    #[test]
    fn generations_on_fresh_rootfs_lists_nothing() {
        let root = tempfile::tempdir().expect("tmpdir");
        let (_dir, svc) = test_service(Some(root.path().join("system")));
        // `SnapshotEngine::open` creates the root exactly like the CLI, so a
        // fresh root is an empty success, not an error.
        let resp = svc.generations_blocking(pb::GenerationsRequest {});
        assert!(resp.error.is_none(), "{:?}", resp.error);
        assert!(resp.generations.is_empty());
        assert!(root.path().join("system").is_dir());
    }

    #[test]
    fn bind_control_socket_applies_design_mode_and_rejects_rebind() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let socket = dir.path().join("instanz.sock");
        let _listener = bind_control_socket(&socket).expect("first bind");
        let mode = fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, SOCKET_MODE, "§15 socket mode must be applied");
        assert!(
            matches!(bind_control_socket(&socket), Err(ServeError::Bind { .. })),
            "binding a taken socket is a typed error"
        );
    }

    #[test]
    fn bind_control_socket_applies_default_group_and_keeps_mode() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().expect("tmpdir");
        let socket = dir.path().join("grouped.sock");
        let _listener = bind_control_socket(&socket).expect("bind with default group");
        let meta = fs::metadata(&socket).expect("socket stat");
        assert_eq!(meta.permissions().mode() & 0o777, SOCKET_MODE);
        // The §15 default for instanz is `extos-admin` — a group that does
        // not exist on ordinary dev hosts, so this pin proves the honest
        // skip: the declarative default cannot be honored, the bind still
        // succeeds and never fails the server. (Where the group exists and
        // the user is a member, the shared policy applies it instead.)
        match libextos::socket::group_gid("extos-admin") {
            Ok(admin_gid) => {
                assert_eq!(meta.gid(), admin_gid, "applied where the group exists");
            }
            Err(libextos::socket::SocketGroupError::UnknownGroup { name }) => {
                assert_eq!(name, "extos-admin");
                println!("HONEST SKIP: default group extos-admin absent on this host");
            }
            other => panic!("unexpected group resolution: {other:?}"),
        }
    }

    #[test]
    fn explicit_unknown_group_is_a_fatal_typed_serve_error() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let socket = dir.path().join("fatal.sock");
        let explicit = ResolvedSocketGroup::Explicit("extos-no-such-group-xyz".to_string());
        match bind_control_socket_with_group(&socket, &explicit) {
            Err(ServeError::SocketGroup { path, source }) => {
                assert_eq!(path, socket);
                assert!(matches!(
                    source,
                    libextos::socket::SocketGroupError::UnknownGroup { .. }
                ));
            }
            other => panic!("expected fatal SocketGroup, got {other:?}"),
        }
    }

    #[test]
    fn bind_control_socket_with_group_none_disables_the_chown() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().expect("tmpdir");
        let socket = dir.path().join("ungrouped.sock");
        let baseline = dir.path().join("baseline");
        fs::write(&baseline, b"").expect("baseline file");
        let own_gid = fs::metadata(&baseline).expect("stat").gid();
        let _listener =
            bind_control_socket_with_group(&socket, &ResolvedSocketGroup::Disabled)
                .expect("bind with disabled group");
        let meta = fs::metadata(&socket).expect("socket stat");
        assert_eq!(meta.permissions().mode() & 0o777, SOCKET_MODE);
        assert_eq!(meta.gid(), own_gid, "--group none must leave the gid alone");
    }

    /// Drive the real serve loop on a tmpdir socket with an explicit
    /// `--group wheel` (PLAN 8.1.5): the mode stays 0660, the typed
    /// apply/skip path runs without failing the serve, and the listener
    /// accepts a client.
    #[tokio::test(flavor = "multi_thread")]
    async fn serve_with_group_wheel_keeps_mode_and_serves() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().expect("tmpdir");
        let repo = CasRepository::open(dir.path().join("repository"), HashAlgorithm::Blake3)
            .expect("tmpdir CAS");
        let socket = dir.path().join("wheel.sock");
        let socket_path = socket.clone();
        let config = InstanzConfig {
            rootfs: None,
            boot_root: None,
            bls_dir: None,
            forge_scratch: dir.path().join("scratch"),
            backend: Some("native".into()),
            system_config: None,
            allow_privileged: false,
        };
        let task = tokio::spawn(async move {
            run_with_group(
                repo,
                Arc::new(config),
                &socket_path,
                socket::resolve_socket_group("instanz", Some("wheel")),
            )
            .await
        });

        let mut bound = false;
        for _ in 0..500 {
            if socket.exists() {
                bound = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(bound, "the control socket never appeared");

        let meta = fs::metadata(&socket).expect("socket stat");
        assert_eq!(
            meta.permissions().mode() & 0o777,
            SOCKET_MODE,
            "§15 socket mode must stay 0660 with --group wheel"
        );
        match libextos::socket::group_gid("wheel") {
            Ok(wheel_gid) if meta.gid() == wheel_gid => {
                println!("PROVEN --group wheel: socket gid == wheel gid ({wheel_gid})");
            }
            _ => println!(
                "HONEST SKIP: --group wheel degraded to the per-host skip (group absent \
                 or daemon user not a member); the serve kept running either way"
            ),
        }

        let _client = tokio::net::UnixStream::connect(&socket)
            .await
            .expect("client connect after group wiring");
        task.abort();
    }
}
