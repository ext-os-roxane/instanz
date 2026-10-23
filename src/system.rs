//! System blueprint (`system.nix`) grammar and package-list expansion for
//! `instanz` (PLAN 2.5.1, 4.1.1, 4.1.2).
//!
//! `instanz` consumes a *system* config — the declarative list of CAS refs that
//! should be woven into one rootfs. It is deliberately a thin layer over
//! [`libextos::config::parse_nix`]: the parser already understands Nix values,
//! so this module only defines which keys exist and how a package entry maps to
//! a [`CasRef`].
//!
//! # Supported grammar
//!
//! ```nix
//! {
//!   # optional — defaults to the config file stem
//!   name = "default";
//!
//!   # optional — package manager of the *roof* the tree boots into.
//!   # One of: arch, debian, alpine, void, rpm (or a full origin name).
//!   # Defaults to the origin providing the most packages.
//!   native_pm = "debian";
//!   # aliases: roof / roof_native_pm / primary_origin / roofs = [ "debian" ]
//!
//!   # optional — kernel version used by `depmod -b <root> <version>`.
//!   # `boot.kernel` takes precedence when both are declared (PLAN 4.1.1).
//!   kernel = "6.8.2-extos";
//!
//!   # optional — boot metadata (PLAN 4.1.1). `modules`, `cmdline` and `initrd`
//!   # are parsed and reported; runlevel-0 forging (PLAN 4.2) consumes them.
//!   boot = {
//!     kernel = "6.8.2-extos";
//!     modules = [ "ext4" "btrfs" ];
//!     cmdline = "quiet nowatchdog";
//!     initrd = "/boot/initramfs-linux.img";
//!   };
//!
//!   # optional — generations root when neither --rootfs nor EXTOS_ROOTFS
//!   # is given (`/runlevel/1/<system>` in production).
//!   root = "/runlevel/1/default";
//!
//!   # optional — BLS `linux` field, required only when EXTOS_BLS_DIR is set.
//!   linux = "/vmlinuz";
//!
//!   # optional — mutable-state mounts (PLAN 4.1.5). `var` and `home` are host
//!   # directories bound into the roof; `var_tmpfs = true` mounts an ephemeral
//!   # tmpfs at <roof>/var instead (ignored when `var` is declared).
//!   var = "/srv/extos/var";
//!   home = "/user";
//!   # var_tmpfs = true;
//!
//!   # optional — named package groups (PLAN 4.1.2). A group is expanded where
//!   # it is referenced; groups may contain refs, other groups (`"@name"`) and
//!   # virtual entries, and must be acyclic (cycles are a hard error).
//!   groups = {
//!     base = [ "debian/bash" "debian/coreutils" ];
//!     workstation = [ "@base" "archlinux/firefox" ];
//!   };
//!
//!   packages = [
//!     "archlinux/htop=3.3.0-1"            # full form
//!     "debian/bash"                       # version defaults to "current"
//!     "ripgrep=14.1.0"                    # origin defaults to archlinux
//!     "@base"                             # group expansion (PLAN 4.1.2)
//!     { group = "workstation"; }          # group expansion, attribute-set form
//!     { virtual = "glibc"; }              # virtual ref → concrete provider
//!     { origin = "alpine"; name = "musl"; version = "1.2.5-r0"; }
//!     { name = "glibc"; }                 # archlinux/current
//!   ];
//!
//!   # parsed and reported only (instanz does not manage services yet)
//!   services = [ "sshd" "chronyd" { name = "networkd"; } ];
//! }
//! ```
//!
//! Every unknown top-level key is ignored so a config can carry keys owned by
//! later phases without breaking `evaluate`.
//!
//! # Package-list expansion (PLAN 4.1.2)
//!
//! [`SystemConfig::expand`] turns the declared entries into a flat, ordered list
//! of concrete [`CasRef`]s:
//!
//! * **groups** are expanded in place (depth-first, declaration order preserved);
//! * **virtual entries** (`refs/virtual/<name>/<version>`) are resolved to the
//!   concrete ref that owns the referenced CAS object; if several refs resolve
//!   to the same object the choice is deterministic (lexicographic
//!   `origin/name/version`) and a note is recorded;
//! * duplicate packages are collapsed to their first declaration, with a note.
//!
//! This is the *instanz-side* expansion required by 4.1.2. Phase 5.1 formalizes
//! resolution into the lockfile; until then the expansion is recomputed on every
//! `evaluate`/`apply` and all notes are surfaced to the operator.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, anyhow, bail};
use libextos::cas::CasRepository;
use libextos::config::{self, NixValue};
use libextos::weaver::CasRef;

/// Default system config path used by `instanz apply` (clap default value).
pub const DEFAULT_CONFIG_PATH: &str = "/config/systems/default.nix";

/// Origin assumed for a bare package name (`"htop"` → `archlinux/htop`).
pub const DEFAULT_ORIGIN: &str = "archlinux";

/// Version assumed when a package entry omits one.
pub const DEFAULT_VERSION: &str = "current";

/// Origin namespace holding virtual refs (`refs/virtual/<name>/<version>`).
pub const VIRTUAL_ORIGIN: &str = "virtual";

/// Prefix that marks a string package entry as a group reference (`"@base"`).
pub const GROUP_PREFIX: char = '@';

/// Maximum group nesting depth; a cycle is detected independently, this is the
/// defensive bound for pathological configs.
const MAX_GROUP_DEPTH: usize = 32;

/// Top-level keys that name the roof's native package manager, in lookup order.
const ROOF_PM_KEYS: [&str; 4] = ["native_pm", "roof_native_pm", "roof", "primary_origin"];

// ─── Boot metadata ──────────────────────────────────────────────

/// Boot-related keys of a system blueprint (PLAN 4.1.1).
///
/// `kernel` is consumed by `depmod`; the other fields are parsed, validated and
/// reported so runlevel-0 forging (PLAN 4.2) can consume them without a second
/// config format.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BootConfig {
    /// Kernel version (single path component) used by `depmod`.
    pub kernel: Option<String>,
    /// Kernel modules to force into the early boot set.
    pub modules: Vec<String>,
    /// Kernel command line.
    pub cmdline: Option<String>,
    /// Initramfs image path, roof-relative or absolute.
    pub initrd: Option<PathBuf>,
}

impl BootConfig {
    fn from_nix(path: &Path, value: &NixValue) -> anyhow::Result<Self> {
        let map = value.as_attrset().ok_or_else(|| {
            anyhow!(
                "{}: `boot` must be an attribute set (kernel/modules/cmdline/initrd)",
                path.display()
            )
        })?;

        let kernel = map
            .get("kernel")
            .and_then(NixValue::as_str)
            .map(str::to_string);
        if let Some(kernel) = &kernel {
            validate_kernel_version(kernel)
                .with_context(|| format!("{}: invalid `boot.kernel`", path.display()))?;
        }

        let modules = match map.get("modules") {
            None => Vec::new(),
            Some(value) => {
                let list = value.as_list().ok_or_else(|| {
                    anyhow!("{}: `boot.modules` must be a list of strings", path.display())
                })?;
                let mut modules = Vec::with_capacity(list.len());
                for item in list {
                    let name = item.as_str().ok_or_else(|| {
                        anyhow!(
                            "{}: `boot.modules` entries must be strings, got {item}",
                            path.display()
                        )
                    })?;
                    if name.trim().is_empty() {
                        bail!("{}: `boot.modules` contains an empty module name", path.display());
                    }
                    modules.push(name.to_string());
                }
                modules
            }
        };

        let cmdline = map
            .get("cmdline")
            .and_then(NixValue::as_str)
            .map(str::to_string);
        let initrd = map
            .get("initrd")
            .and_then(NixValue::as_str)
            .map(PathBuf::from);

        Ok(Self {
            kernel,
            modules,
            cmdline,
            initrd,
        })
    }
}

/// A kernel version must be a single plain path component (`depmod -b <root> …`).
fn validate_kernel_version(kernel: &str) -> anyhow::Result<()> {
    if kernel.trim().is_empty() {
        bail!("kernel version must not be empty");
    }
    if kernel != kernel.trim()
        || kernel.contains('/')
        || kernel.contains('\\')
        || kernel == "."
        || kernel == ".."
        || kernel.contains('\0')
    {
        bail!("kernel version {kernel:?} is not a single path component");
    }
    Ok(())
}

// ─── Package entries ────────────────────────────────────────────

/// One declared `packages` entry before expansion (PLAN 4.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageEntry {
    /// A concrete CAS ref, fully spelled out.
    Ref(CasRef),
    /// A named group declared in `groups` (string form `"@name"`).
    Group(String),
    /// A virtual ref (`refs/virtual/<name>/<version>`) to resolve against the CAS.
    Virtual {
        /// Virtual package name.
        name: String,
        /// Virtual ref version (`current` by default).
        version: String,
    },
}

impl PackageEntry {
    /// Human-readable form used in logs and notes.
    pub fn label(&self) -> String {
        match self {
            PackageEntry::Ref(reference) => reference.label(),
            PackageEntry::Group(name) => format!("@{name}"),
            PackageEntry::Virtual { name, version } => {
                format!("{VIRTUAL_ORIGIN}/{name}/{version}")
            }
        }
    }
}

// ─── Expansion result ───────────────────────────────────────────

/// The flattened package list produced by [`SystemConfig::expand`].
#[derive(Debug, Clone, Default)]
pub struct ExpandedPackages {
    /// Concrete refs in weave order (declaration order, groups expanded in place).
    pub refs: Vec<CasRef>,
    /// For each referenced group: how many entries it expands to.
    ///
    /// Nested groups are counted textually (a member that is also declared
    /// elsewhere still counts here); the woven [`ExpandedPackages::refs`] list is
    /// de-duplicated separately.
    pub groups: BTreeMap<String, usize>,
    /// For each virtual entry: the concrete ref chosen as provider.
    pub virtuals: BTreeMap<String, CasRef>,
    /// Non-fatal notes (duplicates, ambiguous virtual providers, …).
    pub notes: Vec<String>,
}

// ─── System config ──────────────────────────────────────────────

/// A parsed system blueprint.
#[derive(Debug, Clone)]
pub struct SystemConfig {
    /// Path the config was read from.
    pub path: PathBuf,
    /// System name (`name`, else the config file stem).
    pub name: String,
    /// Concrete refs declared directly in `packages` (groups/virtuals excluded).
    ///
    /// Kept for callers that only want the literally-declared refs; the weave
    /// pipeline uses [`SystemConfig::expand`], which also resolves groups and
    /// virtual entries (PLAN 4.1.2).
    pub packages: Vec<CasRef>,
    /// Every declared `packages` entry, in order (4.1.2 input).
    pub entries: Vec<PackageEntry>,
    /// Named package groups declared under `groups`.
    pub groups: BTreeMap<String, Vec<PackageEntry>>,
    /// Boot metadata (`boot = { … }`).
    pub boot: BootConfig,
    /// Roof-native package manager, if the config pins one.
    pub roof_native_pm: Option<String>,
    /// Kernel version for `depmod`: `boot.kernel`, else top-level `kernel`.
    pub kernel: Option<String>,
    /// Generations root, if declared.
    pub root: Option<PathBuf>,
    /// BLS `linux` field, if declared.
    pub linux: Option<PathBuf>,
    /// Host directory to bind onto `<roof>/var` (PLAN 4.1.5).
    pub var: Option<PathBuf>,
    /// Host directory to bind onto `<roof>/home` (PLAN 4.1.5).
    pub home: Option<PathBuf>,
    /// Mount `<roof>/var` as a tmpfs when `var` is not declared (PLAN 4.1.5).
    pub var_tmpfs: bool,
    /// Service names (parsed only).
    pub services: Vec<String>,
}

impl SystemConfig {
    /// Read and parse a `system.nix` file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let value = config::parse_nix_file(path)
            .with_context(|| format!("cannot parse system config {}", path.display()))?;
        Self::from_nix(path, &value)
    }

    /// Parse an already-tokenized config (keeps [`Self::load`] testable without
    /// the filesystem).
    pub fn from_nix(path: &Path, value: &NixValue) -> anyhow::Result<Self> {
        let map = value
            .as_attrset()
            .ok_or_else(|| anyhow!("{}: the system config must be an attribute set", path.display()))?;

        let name = map
            .get("name")
            .and_then(NixValue::as_str)
            .map(str::to_string)
            .or_else(|| {
                path.file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or_else(|| "default".to_string());

        let groups = match map.get("groups") {
            None => BTreeMap::new(),
            Some(value) => parse_groups(path, value)?,
        };

        let packaging = map
            .get("packages")
            .ok_or_else(|| anyhow!("{}: missing required `packages = [ … ];` list", path.display()))?;
        let list = packaging.as_list().ok_or_else(|| {
            anyhow!(
                "{}: `packages` must be a list of strings or attribute sets",
                path.display()
            )
        })?;

        let mut entries = Vec::with_capacity(list.len());
        for entry in list {
            entries.push(parse_package_entry(entry).with_context(|| {
                format!("{}: invalid `packages` entry {entry}", path.display())
            })?);
        }
        // Every referenced group must exist — catch typos at parse time.
        for entry in &entries {
            if let PackageEntry::Group(group) = entry {
                if !groups.contains_key(group) {
                    bail!(
                        "{}: `packages` references undeclared group `@{group}`",
                        path.display()
                    );
                }
            }
        }

        let packages: Vec<CasRef> = entries
            .iter()
            .filter_map(|entry| match entry {
                PackageEntry::Ref(reference) => Some(reference.clone()),
                _ => None,
            })
            .collect();

        let boot = match map.get("boot") {
            None => BootConfig::default(),
            Some(value) => BootConfig::from_nix(path, value)?,
        };

        let legacy_kernel = map.get("kernel").and_then(NixValue::as_str).map(str::to_string);
        if let Some(kernel) = &legacy_kernel {
            validate_kernel_version(kernel)
                .with_context(|| format!("{}: invalid top-level `kernel`", path.display()))?;
        }
        // `boot.kernel` wins when both are declared: the nested form is the
        // documented Phase-4 location, the top-level one is the Phase-2 alias.
        let kernel = boot.kernel.clone().or(legacy_kernel);

        let roof_native_pm = roof_pm(map);
        let root = map.get("root").and_then(NixValue::as_str).map(PathBuf::from);
        let linux = map.get("linux").and_then(NixValue::as_str).map(PathBuf::from);
        let var = map.get("var").and_then(NixValue::as_str).map(PathBuf::from);
        let home = map.get("home").and_then(NixValue::as_str).map(PathBuf::from);
        let var_tmpfs = map
            .get("var_tmpfs")
            .and_then(NixValue::as_bool)
            .unwrap_or(false);

        let services = match map.get("services") {
            None => Vec::new(),
            Some(v) => parse_services(v)
                .with_context(|| format!("{}: invalid `services` list", path.display()))?,
        };

        Ok(Self {
            path: path.to_path_buf(),
            name,
            packages,
            entries,
            groups,
            boot,
            roof_native_pm,
            kernel,
            root,
            linux,
            var,
            home,
            var_tmpfs,
            services,
        })
    }

    /// Mount sources declared by this system (PLAN 4.1.5).
    pub fn mount_sources(&self) -> crate::mount::MountSources {
        crate::mount::MountSources::new(self.var.clone(), self.home.clone(), self.var_tmpfs)
    }

    /// Expand groups and virtual entries into concrete refs (PLAN 4.1.2).
    ///
    /// `repo` is consulted for virtual refs only; concrete refs are not checked
    /// for presence here (the apply pipeline reports missing refs separately).
    /// Order is declaration order with groups expanded in place and de-duplicated
    /// by `(origin, name)` — the weaver plans one node per package, so a second
    /// declaration of the same package could never produce a second node.
    pub fn expand(&self, repo: &CasRepository) -> anyhow::Result<ExpandedPackages> {
        let mut expanded = ExpandedPackages::default();
        let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
        let mut stack: Vec<String> = Vec::new();
        self.expand_entries(repo, &self.entries, &mut expanded, &mut seen, &mut stack)?;
        Ok(expanded)
    }

    /// Depth-first expansion worker shared by the top level and groups.
    #[allow(clippy::too_many_arguments)]
    fn expand_entries(
        &self,
        repo: &CasRepository,
        entries: &[PackageEntry],
        expanded: &mut ExpandedPackages,
        seen: &mut BTreeSet<(String, String)>,
        stack: &mut Vec<String>,
    ) -> anyhow::Result<()> {
        for entry in entries {
            match entry {
                PackageEntry::Ref(reference) => {
                    let key = (reference.origin.clone(), reference.name.clone());
                    if !seen.insert(key) {
                        expanded.notes.push(format!(
                            "duplicate package {} collapsed (first declaration wins)",
                            reference.label()
                        ));
                        continue;
                    }
                    expanded.refs.push(reference.clone());
                }
                PackageEntry::Group(group) => {
                    if stack.contains(group) {
                        let mut chain = stack.clone();
                        chain.push(group.clone());
                        bail!(
                            "{}: group cycle detected: {}",
                            self.path.display(),
                            chain
                                .iter()
                                .map(|name| format!("@{name}"))
                                .collect::<Vec<_>>()
                                .join(" → ")
                        );
                    }
                    if stack.len() >= MAX_GROUP_DEPTH {
                        bail!(
                            "{}: group nesting deeper than {MAX_GROUP_DEPTH} at `@{group}`",
                            self.path.display()
                        );
                    }
                    let members = self.groups.get(group).ok_or_else(|| {
                        anyhow!(
                            "{}: unknown group `@{group}` (declared groups: {})",
                            self.path.display(),
                            if self.groups.is_empty() {
                                "none".to_string()
                            } else {
                                self.groups
                                    .keys()
                                    .map(|name| format!("@{name}"))
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            }
                        )
                    })?;
                    if !expanded.groups.contains_key(group) {
                        let size = self.group_size(group, &mut Vec::new());
                        expanded.groups.insert(group.clone(), size);
                    }
                    stack.push(group.clone());
                    let result = self.expand_entries(repo, members, expanded, seen, stack);
                    stack.pop();
                    result?;
                }
                PackageEntry::Virtual { name, version } => {
                    let chosen = self.resolve_virtual(repo, name, version, expanded)?;
                    let key = (chosen.origin.clone(), chosen.name.clone());
                    if !seen.insert(key) {
                        expanded.notes.push(format!(
                            "virtual {VIRTUAL_ORIGIN}/{name} resolved to {} which is already declared",
                            chosen.label()
                        ));
                        continue;
                    }
                    expanded
                        .virtuals
                        .insert(format!("{VIRTUAL_ORIGIN}/{name}"), chosen.clone());
                    expanded.refs.push(chosen);
                }
            }
        }
        Ok(())
    }

    /// Number of entries a group expands to, counting nested groups textually.
    ///
    /// Cycles are reported by [`SystemConfig::expand_entries`]; here a repeated
    /// group contributes `0` instead of recursing forever.
    fn group_size(&self, name: &str, visiting: &mut Vec<String>) -> usize {
        if visiting.iter().any(|seen| seen == name) {
            return 0;
        }
        let Some(members) = self.groups.get(name) else {
            return 0;
        };
        visiting.push(name.to_string());
        let mut total = 0;
        for member in members {
            match member {
                PackageEntry::Ref(_) | PackageEntry::Virtual { .. } => total += 1,
                PackageEntry::Group(nested) => total += self.group_size(nested, visiting),
            }
        }
        visiting.pop();
        total
    }

    /// Resolve a virtual ref to the concrete ref that owns the same CAS object.
    fn resolve_virtual(
        &self,
        repo: &CasRepository,
        name: &str,
        version: &str,
        expanded: &mut ExpandedPackages,
    ) -> anyhow::Result<CasRef> {
        let hash = repo
            .resolve_ref(VIRTUAL_ORIGIN, name, version)
            .with_context(|| {
                format!(
                    "{}: cannot resolve virtual ref {VIRTUAL_ORIGIN}/{name}/{version} in {} \
                     (create it with `pkt` or declare a concrete package instead)",
                    self.path.display(),
                    repo.root.display()
                )
            })?;

        if let Some(known) = expanded.virtuals.get(&format!("{VIRTUAL_ORIGIN}/{name}")) {
            return Ok(known.clone());
        }

        let mut providers: Vec<CasRef> = Vec::new();
        for entry in repo.list_refs().with_context(|| {
            format!("cannot enumerate CAS refs in {}", repo.root.display())
        })? {
            if entry.origin == VIRTUAL_ORIGIN {
                continue;
            }
            if repo
                .resolve_ref(&entry.origin, &entry.name, &entry.version)
                .is_ok_and(|candidate| candidate == hash)
            {
                providers.push(CasRef::from(entry));
            }
        }

        providers.sort();
        let chosen = providers.first().cloned().ok_or_else(|| {
            anyhow!(
                "{}: virtual ref {VIRTUAL_ORIGIN}/{name}/{version} points at object {}, \
                 but no concrete ref resolves to it",
                self.path.display(),
                &hash[..hash.len().min(16)]
            )
        })?;
        if providers.len() > 1 {
            expanded.notes.push(format!(
                "virtual {VIRTUAL_ORIGIN}/{name} is ambiguous ({} providers); chose {} deterministically",
                providers.len(),
                chosen.label()
            ));
        }
        Ok(chosen)
    }
}

// ─── Parsing helpers ────────────────────────────────────────────

/// Extract the roof's native package manager.
///
/// `native_pm` / `roof_native_pm` / `roof` / `primary_origin` are checked first;
/// the plural `roofs` (a string, or a list whose first entry wins) is accepted
/// as an alias so a config can name the roofs it targets without extra syntax.
fn roof_pm(map: &std::collections::BTreeMap<String, NixValue>) -> Option<String> {
    for key in ROOF_PM_KEYS {
        if let Some(value) = map.get(key).and_then(NixValue::as_str) {
            let pm = normalize_pm(value);
            if !pm.is_empty() {
                return Some(pm);
            }
        }
    }

    let roofs = map.get("roofs")?;
    let first = match roofs {
        NixValue::String(name) => Some(name.as_str()),
        NixValue::List(items) => items.iter().find_map(NixValue::as_str),
        _ => None,
    }?;
    let pm = normalize_pm(first);
    (!pm.is_empty()).then_some(pm)
}

/// Parse the `groups = { name = [ … ]; };` attribute set.
fn parse_groups(path: &Path, value: &NixValue) -> anyhow::Result<BTreeMap<String, Vec<PackageEntry>>> {
    let map = value
        .as_attrset()
        .ok_or_else(|| anyhow!("{}: `groups` must be an attribute set", path.display()))?;
    let mut groups = BTreeMap::new();
    for (name, members) in map {
        if name.trim().is_empty() {
            bail!("{}: group names must not be empty", path.display());
        }
        let list = members.as_list().ok_or_else(|| {
            anyhow!(
                "{}: group `@{name}` must be a list of package entries",
                path.display()
            )
        })?;
        let mut parsed = Vec::with_capacity(list.len());
        for member in list {
            parsed.push(parse_package_entry(member).with_context(|| {
                format!("{}: invalid entry in group `@{name}`: {member}", path.display())
            })?);
        }
        groups.insert(name.clone(), parsed);
    }
    Ok(groups)
}

/// Parse one `packages`/group entry (string spec or attribute set).
fn parse_package_entry(entry: &NixValue) -> anyhow::Result<PackageEntry> {
    match entry {
        NixValue::String(spec) => {
            let spec = spec.trim();
            if let Some(group) = spec.strip_prefix(GROUP_PREFIX) {
                if group.is_empty() {
                    bail!("empty group reference `{spec}`");
                }
                return Ok(PackageEntry::Group(group.to_string()));
            }
            parse_package_spec(spec).map(PackageEntry::Ref)
        }
        NixValue::AttrSet(map) => {
            if let Some(virtual_ref) = map.get("virtual") {
                let name = virtual_ref
                    .as_str()
                    .ok_or_else(|| anyhow!("`virtual` must be a string"))?;
                validate_component("virtual name", name)?;
                let version = map
                    .get("version")
                    .and_then(NixValue::as_str)
                    .unwrap_or(DEFAULT_VERSION);
                validate_component("version", version)?;
                return Ok(PackageEntry::Virtual {
                    name: name.to_string(),
                    version: version.to_string(),
                });
            }
            if let Some(group) = map.get("group") {
                let name = group
                    .as_str()
                    .ok_or_else(|| anyhow!("`group` must be a string"))?;
                if name.trim().is_empty() {
                    bail!("`group` must not be empty");
                }
                return Ok(PackageEntry::Group(name.to_string()));
            }
            let name = map
                .get("name")
                .and_then(NixValue::as_str)
                .ok_or_else(|| anyhow!("attribute-set entry is missing `name`"))?;
            let origin = map
                .get("origin")
                .and_then(NixValue::as_str)
                .unwrap_or(DEFAULT_ORIGIN);
            let version = map
                .get("version")
                .and_then(NixValue::as_str)
                .unwrap_or(DEFAULT_VERSION);
            validate_ref(origin, name, version).map(PackageEntry::Ref)
        }
        other => bail!("expected a string or an attribute set, got {other}"),
    }
}

/// Parse `[origin/]name[=version]`.
///
/// - `origin/name` → version defaults to [`DEFAULT_VERSION`]
/// - `name`        → origin defaults to [`DEFAULT_ORIGIN`]
pub fn parse_package_spec(spec: &str) -> anyhow::Result<CasRef> {
    let spec = spec.trim();
    if spec.is_empty() {
        bail!("empty package spec");
    }

    let (locator, version) = match spec.split_once('=') {
        Some((locator, version)) => {
            let version = version.trim();
            if version.is_empty() {
                bail!("`{spec}` has an empty version after `=`");
            }
            (locator.trim(), version)
        }
        None => (spec, DEFAULT_VERSION),
    };

    let (origin, name) = match locator.split_once('/') {
        Some((origin, name)) => {
            if origin.is_empty() || name.is_empty() || name.contains('/') {
                bail!("expected `[origin/]name[=version]`, got `{spec}`");
            }
            (origin, name)
        }
        None => (DEFAULT_ORIGIN, locator),
    };

    validate_ref(origin, name, version)
}

/// Validate a single path component used as (or in) a ref.
fn validate_component(what: &str, value: &str) -> anyhow::Result<()> {
    if value.is_empty() {
        bail!("{what} must not be empty");
    }
    if value.contains('/') || value == "." || value == ".." || value.contains('\0') {
        bail!("{what} `{value}` is not a single path component");
    }
    Ok(())
}

/// Reject ref components that could escape the `refs/<origin>/<name>/<version>`
/// layout (the CAS joins them onto a path).
fn validate_ref(origin: &str, name: &str, version: &str) -> anyhow::Result<CasRef> {
    for (what, value) in [("origin", origin), ("name", name), ("version", version)] {
        validate_component(what, value)?;
    }
    Ok(CasRef::new(origin, name, version))
}

/// Fold a friendly spelling (`arch`, `pacman`, `dpkg`, …) to a manifest origin.
///
/// Unknown spellings are passed through lowercased: a roof PM may name a future
/// origin, and the phantom writers simply ignore origins they do not handle.
fn normalize_pm(pm: &str) -> String {
    match pm.trim().to_ascii_lowercase().as_str() {
        "arch" | "pacman" => "archlinux".to_string(),
        "dpkg" | "apt" => "debian".to_string(),
        "apk" => "alpine".to_string(),
        "xbps" => "void".to_string(),
        "dnf" | "yum" | "zypper" | "fedora" | "rhel" | "centos" | "suse" => "rpm".to_string(),
        other => other.to_string(),
    }
}

/// Extract service names from `services = [ "a" { name = "b"; } ];`.
fn parse_services(value: &NixValue) -> anyhow::Result<Vec<String>> {
    let list = value
        .as_list()
        .ok_or_else(|| anyhow!("`services` must be a list"))?;
    let mut names = Vec::with_capacity(list.len());
    for item in list {
        match item {
            NixValue::String(name) => names.push(name.clone()),
            NixValue::AttrSet(map) => {
                let name = map
                    .get("name")
                    .and_then(NixValue::as_str)
                    .ok_or_else(|| anyhow!("service entry is missing `name`"))?;
                names.push(name.to_string());
            }
            other => bail!("service entry must be a string or an attribute set, got {other}"),
        }
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libextos::types::HashAlgorithm;

    fn parse(text: &str) -> anyhow::Result<SystemConfig> {
        let value = config::parse_nix(text)?;
        SystemConfig::from_nix(Path::new("default.nix"), &value)
    }

    /// Open a tempdir CAS and publish a one-file payload as `origin/name`.
    ///
    /// The payload bytes depend only on `name/version`, so two origins packaging
    /// the same thing produce the very same CAS object (used by the ambiguous
    /// virtual-provider test).
    fn publish(repo: &CasRepository, origin: &str, name: &str, version: &str) -> String {
        let staging = tempfile::tempdir().unwrap();
        let src = staging.path().join(name);
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("payload"), format!("{name}/{version}")).unwrap();
        let hash = repo.store_directory(&src).unwrap();
        repo.write_manifest(
            &hash,
            &format!(
                "{{ identity = {{ origin = \"{origin}\"; name = \"{name}\"; version = \"{version}\"; }}; }}"
            ),
        )
        .unwrap();
        repo.create_ref(origin, name, version, &hash).unwrap();
        hash
    }

    #[test]
    fn parses_string_and_attrset_packages() {
        let cfg = parse(
            r#"{
                name = "workstation";
                native_pm = "debian";
                kernel = "6.8.2-extos";
                packages = [
                    "archlinux/htop=3.3.0-1"
                    "debian/bash"
                    "ripgrep=14.1.0"
                    { name = "musl"; origin = "alpine"; version = "1.2.5-r0"; }
                    { name = "glibc"; }
                ];
                services = [ "sshd" { name = "networkd"; } ];
            }"#,
        )
        .unwrap();

        assert_eq!(cfg.name, "workstation");
        assert_eq!(cfg.roof_native_pm.as_deref(), Some("debian"));
        assert_eq!(cfg.kernel.as_deref(), Some("6.8.2-extos"));
        assert_eq!(cfg.packages.len(), 5);
        assert_eq!(cfg.entries.len(), 5);
        assert_eq!(
            cfg.packages[0],
            CasRef::new("archlinux", "htop", "3.3.0-1")
        );
        assert_eq!(cfg.packages[1], CasRef::new("debian", "bash", "current"));
        assert_eq!(cfg.packages[2], CasRef::new("archlinux", "ripgrep", "14.1.0"));
        assert_eq!(cfg.packages[3], CasRef::new("alpine", "musl", "1.2.5-r0"));
        assert_eq!(cfg.packages[4], CasRef::new("archlinux", "glibc", "current"));
        assert_eq!(cfg.services, vec!["sshd", "networkd"]);
    }

    #[test]
    fn name_defaults_to_file_stem() {
        let cfg = parse(r#"{ packages = []; }"#).unwrap();
        assert_eq!(cfg.name, "default");
        assert!(cfg.packages.is_empty());
        assert!(cfg.roof_native_pm.is_none());
        assert!(cfg.root.is_none());
        assert_eq!(cfg.boot, BootConfig::default());
    }

    #[test]
    fn missing_packages_is_an_error() {
        let err = parse(r#"{ name = "x"; }"#).unwrap_err().to_string();
        assert!(err.contains("packages"), "{err}");
    }

    #[test]
    fn path_traversal_is_rejected() {
        for spec in ["../etc", "archlinux/../x", "a/b/c", "x/"] {
            assert!(parse_package_spec(spec).is_err(), "{spec} should be rejected");
        }
    }

    #[test]
    fn roofs_list_is_accepted_as_an_alias() {
        let cfg = parse(r#"{ roofs = [ "alpine" ]; packages = [ "x" ]; }"#).unwrap();
        assert_eq!(cfg.roof_native_pm.as_deref(), Some("alpine"));

        let cfg = parse(r#"{ roofs = "arch"; packages = [ "x" ]; }"#).unwrap();
        assert_eq!(cfg.roof_native_pm.as_deref(), Some("archlinux"));
    }

    #[test]
    fn friendly_pm_spellings_are_normalized() {
        for (input, expected) in [
            ("arch", "archlinux"),
            ("pacman", "archlinux"),
            ("dpkg", "debian"),
            ("apk", "alpine"),
            ("xbps", "void"),
            ("dnf", "rpm"),
            ("nix", "nix"),
        ] {
            assert_eq!(normalize_pm(input), expected, "input {input}");
        }
    }

    // ── 4.1.1 boot block ───────────────────────────────────────

    #[test]
    fn boot_block_is_parsed_and_kernel_precedence_is_documented() {
        let cfg = parse(
            r#"{
                kernel = "6.6.1-legacy";
                boot = {
                    kernel = "6.8.2-extos";
                    modules = [ "ext4" "btrfs" ];
                    cmdline = "quiet nowatchdog";
                    initrd = "/boot/initramfs-linux.img";
                };
                packages = [ "bash" ];
            }"#,
        )
        .unwrap();

        assert_eq!(cfg.boot.kernel.as_deref(), Some("6.8.2-extos"));
        assert_eq!(cfg.boot.modules, vec!["ext4", "btrfs"]);
        assert_eq!(cfg.boot.cmdline.as_deref(), Some("quiet nowatchdog"));
        assert_eq!(
            cfg.boot.initrd.as_deref(),
            Some(Path::new("/boot/initramfs-linux.img"))
        );
        // `boot.kernel` wins over the legacy top-level alias.
        assert_eq!(cfg.kernel.as_deref(), Some("6.8.2-extos"));

        // Only the legacy key: it supplies the effective kernel.
        let cfg = parse(r#"{ kernel = "6.6.1"; packages = []; }"#).unwrap();
        assert_eq!(cfg.kernel.as_deref(), Some("6.6.1"));
        assert_eq!(cfg.boot.kernel, None);
    }

    #[test]
    fn invalid_boot_values_are_typed_errors() {
        for config in [
            r#"{ boot = "nope"; packages = []; }"#,
            r#"{ boot = { kernel = "../etc"; }; packages = []; }"#,
            r#"{ boot = { modules = "ext4"; }; packages = []; }"#,
            r#"{ boot = { modules = [ 3 ]; }; packages = []; }"#,
            r#"{ kernel = "a/b"; packages = []; }"#,
        ] {
            let err = parse(config).unwrap_err().to_string();
            assert!(
                err.contains("boot") || err.contains("kernel"),
                "{config}: {err}"
            );
        }
    }

    // ── 4.1.2 groups & virtuals ────────────────────────────────

    #[test]
    fn groups_expand_in_place_and_deduplicate() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = CasRepository::open(tmp.path(), HashAlgorithm::Blake3).unwrap();
        let cfg = parse(
            r#"{
                groups = {
                    base = [ "debian/bash" "debian/coreutils" ];
                    workstation = [ "@base" "archlinux/firefox" ];
                };
                packages = [ "archlinux/vim" "@base" { group = "workstation"; } "debian/bash" ];
            }"#,
        )
        .unwrap();

        let expanded = cfg.expand(&repo).unwrap();
        assert_eq!(
            expanded.refs,
            vec![
                CasRef::new("archlinux", "vim", "current"),
                CasRef::new("debian", "bash", "current"),
                CasRef::new("debian", "coreutils", "current"),
                CasRef::new("archlinux", "firefox", "current"),
            ]
        );
        // `base` contributed twice textually (direct + inside workstation) but
        // only its distinct members are woven.
        assert_eq!(expanded.groups.get("base"), Some(&2));
        assert_eq!(expanded.groups.get("workstation"), Some(&3));
        assert!(expanded.notes.iter().any(|n| n.contains("duplicate package")));
        // The literal `packages` projection still only lists declared refs.
        assert_eq!(cfg.packages.len(), 2);
    }

    #[test]
    fn undeclared_and_cyclic_groups_are_hard_errors() {
        let err = parse(
            r#"{ groups = { base = [ "bash" ]; }; packages = [ "@missing" ]; }"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("undeclared group"), "{err}");

        let cfg = parse(
            r#"{
                groups = { a = [ "@b" ]; b = [ "@a" ]; };
                packages = [ "@a" ];
            }"#,
        )
        .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let repo = CasRepository::open(tmp.path(), HashAlgorithm::Blake3).unwrap();
        let err = cfg.expand(&repo).unwrap_err().to_string();
        assert!(err.contains("cycle"), "{err}");
        assert!(err.contains("@a"), "{err}");
    }

    #[test]
    fn virtual_entries_resolve_to_the_concrete_provider() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = CasRepository::open(tmp.path(), HashAlgorithm::Blake3).unwrap();
        let hash = publish(&repo, "archlinux", "glibc", "2.39");
        repo.create_virtual_ref("glibc", "2.39", "archlinux", "glibc")
            .unwrap();
        assert_eq!(repo.resolve_ref("virtual", "glibc", "2.39").unwrap(), hash);

        let cfg = parse(
            r#"{ packages = [ { virtual = "glibc"; version = "2.39"; } "bash" ]; }"#,
        )
        .unwrap();
        let expanded = cfg.expand(&repo).unwrap();
        assert_eq!(
            expanded.refs,
            vec![
                CasRef::new("archlinux", "glibc", "2.39"),
                CasRef::new("archlinux", "bash", "current"),
            ]
        );
        assert_eq!(
            expanded.virtuals.get("virtual/glibc"),
            Some(&CasRef::new("archlinux", "glibc", "2.39"))
        );
    }

    #[test]
    fn missing_virtual_ref_is_a_named_error() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = CasRepository::open(tmp.path(), HashAlgorithm::Blake3).unwrap();
        let cfg = parse(r#"{ packages = [ { virtual = "glibc"; } ]; }"#).unwrap();
        let err = cfg.expand(&repo).unwrap_err().to_string();
        assert!(err.contains("virtual/glibc/current"), "{err}");
        assert!(err.contains("concrete package"), "{err}");
    }

    #[test]
    fn virtual_ref_with_no_concrete_owner_is_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = CasRepository::open(tmp.path(), HashAlgorithm::Blake3).unwrap();
        // An object that no ref points at.
        let staging = tempfile::tempdir().unwrap();
        std::fs::write(staging.path().join("x"), b"x").unwrap();
        let hash = repo.store_directory(staging.path()).unwrap();
        repo.create_ref("virtual", "ghost", "1.0", &hash).unwrap();

        let cfg = parse(r#"{ packages = [ { virtual = "ghost"; version = "1.0"; } ]; }"#).unwrap();
        let err = cfg.expand(&repo).unwrap_err().to_string();
        assert!(err.contains("no concrete ref"), "{err}");
    }

    #[test]
    fn ambiguous_virtual_picks_deterministically_and_notes_it() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = CasRepository::open(tmp.path(), HashAlgorithm::Blake3).unwrap();
        // Two origins with byte-identical payloads ⇒ same object hash.
        let a = publish(&repo, "debian", "libc6", "2.39");
        let b = publish(&repo, "alpine", "libc6", "2.39");
        assert_eq!(a, b, "fixture must share one CAS object");
        repo.create_ref("virtual", "glibc", "current", &a).unwrap();

        let cfg = parse(r#"{ packages = [ { virtual = "glibc"; } ]; }"#).unwrap();
        let expanded = cfg.expand(&repo).unwrap();
        // Lexicographic origin order: alpine before debian.
        assert_eq!(expanded.refs, vec![CasRef::new("alpine", "libc6", "2.39")]);
        assert!(expanded
            .notes
            .iter()
            .any(|n| n.contains("ambiguous") && n.contains("2 providers")));
    }

    #[test]
    fn expansion_preserves_declaration_order_across_mixed_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = CasRepository::open(tmp.path(), HashAlgorithm::Blake3).unwrap();
        let cfg = parse(
            r#"{
                groups = { tools = [ "debian/coreutils" ]; };
                packages = [ "debian/bash" "@tools" "debian/dash" ];
            }"#,
        )
        .unwrap();
        let names: Vec<String> = cfg
            .expand(&repo)
            .unwrap()
            .refs
            .iter()
            .map(|r| r.name.clone())
            .collect();
        assert_eq!(names, vec!["bash", "coreutils", "dash"]);
    }

    #[test]
    fn mount_sources_are_taken_from_the_config() {
        let cfg = parse(
            r#"{
                var = "/srv/extos/var";
                home = "/user";
                var_tmpfs = true;
                packages = [];
            }"#,
        )
        .unwrap();
        let sources = cfg.mount_sources();
        assert_eq!(sources.var.as_deref(), Some(Path::new("/srv/extos/var")));
        assert_eq!(sources.home.as_deref(), Some(Path::new("/user")));
        assert!(sources.var_tmpfs);

        let cfg = parse(r#"{ packages = []; }"#).unwrap();
        let sources = cfg.mount_sources();
        assert!(sources.var.is_none() && sources.home.is_none());
        assert!(!sources.var_tmpfs);
    }
}
