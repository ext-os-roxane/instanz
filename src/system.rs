//! System blueprint (`system.nix`) grammar for `instanz` (PLAN 2.5.1).
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
//!   kernel = "6.8.2-extos";
//!
//!   # optional — generations root when neither --rootfs nor EXTOS_ROOTFS
//!   # is given (`/runlevel/1/<system>` in production).
//!   root = "/runlevel/1/default";
//!
//!   # optional — BLS `linux` field, required only when EXTOS_BLS_DIR is set.
//!   linux = "/vmlinuz";
//!
//!   packages = [
//!     "archlinux/htop=3.3.0-1"            # full form
//!     "debian/bash"                       # version defaults to "current"
//!     "ripgrep=14.1.0"                    # origin defaults to archlinux
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

use std::path::{Path, PathBuf};

use anyhow::{Context as _, anyhow, bail};
use libextos::config::{self, NixValue};
use libextos::weaver::CasRef;

/// Default system config path used by `instanz apply` (clap default value).
pub const DEFAULT_CONFIG_PATH: &str = "/config/systems/default.nix";

/// Origin assumed for a bare package name (`"htop"` → `archlinux/htop`).
pub const DEFAULT_ORIGIN: &str = "archlinux";

/// Version assumed when a package entry omits one.
pub const DEFAULT_VERSION: &str = "current";

/// Top-level keys that name the roof's native package manager, in lookup order.
const ROOF_PM_KEYS: [&str; 4] = ["native_pm", "roof_native_pm", "roof", "primary_origin"];
/// A parsed system blueprint.
#[derive(Debug, Clone)]
pub struct SystemConfig {
    /// Path the config was read from.
    pub path: PathBuf,
    /// System name (`name`, else the config file stem).
    pub name: String,
    /// Packages to weave, in declaration order.
    pub packages: Vec<CasRef>,
    /// Roof-native package manager, if the config pins one.
    pub roof_native_pm: Option<String>,
    /// Kernel version for `depmod`, if declared.
    pub kernel: Option<String>,
    /// Generations root, if declared.
    pub root: Option<PathBuf>,
    /// BLS `linux` field, if declared.
    pub linux: Option<PathBuf>,
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

        let packaging = map
            .get("packages")
            .ok_or_else(|| anyhow!("{}: missing required `packages = [ … ];` list", path.display()))?;
        let entries = packaging.as_list().ok_or_else(|| {
            anyhow!(
                "{}: `packages` must be a list of strings or attribute sets",
                path.display()
            )
        })?;

        let mut packages = Vec::with_capacity(entries.len());
        for entry in entries {
            packages.push(parse_package_entry(entry).with_context(|| {
                format!("{}: invalid `packages` entry {entry}", path.display())
            })?);
        }

        let roof_native_pm = roof_pm(map);

        let kernel = map.get("kernel").and_then(NixValue::as_str).map(str::to_string);
        let root = map.get("root").and_then(NixValue::as_str).map(PathBuf::from);
        let linux = map.get("linux").and_then(NixValue::as_str).map(PathBuf::from);

        let services = match map.get("services") {
            None => Vec::new(),
            Some(v) => parse_services(v)
                .with_context(|| format!("{}: invalid `services` list", path.display()))?,
        };

        Ok(Self {
            path: path.to_path_buf(),
            name,
            packages,
            roof_native_pm,
            kernel,
            root,
            linux,
            services,
        })
    }
}

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

/// Parse one `packages` entry (string spec or attribute set).
fn parse_package_entry(entry: &NixValue) -> anyhow::Result<CasRef> {
    match entry {
        NixValue::String(spec) => parse_package_spec(spec),
        NixValue::AttrSet(map) => {
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
            validate_ref(origin, name, version)
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

/// Reject ref components that could escape the `refs/<origin>/<name>/<version>`
/// layout (the CAS joins them onto a path).
fn validate_ref(origin: &str, name: &str, version: &str) -> anyhow::Result<CasRef> {
    for (what, value) in [("origin", origin), ("name", name), ("version", version)] {
        if value.is_empty() {
            bail!("{what} must not be empty");
        }
        if value.contains('/') || value == "." || value == ".." || value.contains('\0') {
            bail!("{what} `{value}` is not a single path component");
        }
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

    fn parse(text: &str) -> anyhow::Result<SystemConfig> {
        let value = config::parse_nix(text)?;
        SystemConfig::from_nix(Path::new("default.nix"), &value)
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
}
