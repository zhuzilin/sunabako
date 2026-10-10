use anyhow::{bail, ensure, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodeConfig {
    pub memory_capacity_bytes: u64,
    pub memory_overcommit: f64,
    pub max_sandboxes: usize,
    pub uid_start: u32,
    pub gpu_slots_per_device: usize,
    pub cgroup_parent: Option<PathBuf>,
    pub monitor_interval_ms: u64,
    /// Explicitly opt into bounded development tests when the platform offers no cgroup delegation.
    /// This never provides a hard aggregate memory guarantee.
    pub allow_unbounded_memory_for_tests: bool,
    pub proot_binary: Option<PathBuf>,
}
impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            memory_capacity_bytes: 8 << 30,
            memory_overcommit: 1.0,
            max_sandboxes: 128,
            uid_start: 60000,
            gpu_slots_per_device: 4,
            cgroup_parent: None,
            monitor_interval_ms: 25,
            allow_unbounded_memory_for_tests: false,
            proot_binary: None,
        }
    }
}
impl NodeConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.memory_capacity_bytes >= 16 << 20,
            "node memory capacity must be >= 16 MiB"
        );
        ensure!(
            self.memory_overcommit.is_finite() && (1.0..=100.0).contains(&self.memory_overcommit),
            "memory_overcommit must be 1..100"
        );
        ensure!(
            (1..=4096).contains(&self.max_sandboxes),
            "max_sandboxes must be 1..4096"
        );
        ensure!(
            self.uid_start >= 10000
                && self
                    .uid_start
                    .checked_add(self.max_sandboxes as u32)
                    .is_some(),
            "invalid dedicated UID range"
        );
        ensure!(
            (1..=1000).contains(&self.monitor_interval_ms),
            "monitor interval must be 1..1000 ms"
        );
        ensure!(self.gpu_slots_per_device > 0, "GPU slots must be positive");
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    pub id: String,
    pub rootfs: PathBuf,
    pub memory_bytes: u64,
    #[serde(default = "hard_memory")]
    pub memory_mode: String,
    #[serde(default = "pids_default")]
    pub pids_max: u64,
    #[serde(default)]
    pub gpus: Vec<u32>,
    #[serde(default = "shared")]
    pub gpu_mode: String,
    #[serde(default = "none")]
    pub network: String,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub mounts: Vec<Mount>,
    #[serde(default = "native")]
    pub runtime: String,
}
fn native() -> String {
    "native".into()
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mount {
    pub source: PathBuf,
    pub target: PathBuf,
    #[serde(default)]
    pub readonly: bool,
}
fn hard_memory() -> String {
    "cgroup".into()
}
fn pids_default() -> u64 {
    256
}
fn shared() -> String {
    "shared".into()
}
fn none() -> String {
    "none".into()
}
impl Spec {
    pub fn validate(&self) -> Result<()> {
        valid_id(&self.id)?;
        ensure!(
            self.rootfs.is_absolute() && self.rootfs.join("bin/sh").exists(),
            "rootfs must be an absolute Linux rootfs containing /bin/sh"
        );
        ensure!(
            self.memory_bytes >= 16 << 20,
            "memory_bytes must be >= 16 MiB"
        );
        ensure!(
            matches!(self.memory_mode.as_str(), "cgroup" | "rss"),
            "memory_mode must be cgroup or rss"
        );
        ensure!(
            matches!(self.runtime.as_str(), "native" | "proot"),
            "runtime must be native or proot"
        );
        ensure!(
            matches!(self.network.as_str(), "none" | "host"),
            "network must be none or host"
        );
        ensure!(
            matches!(self.gpu_mode.as_str(), "shared" | "exclusive"),
            "GPU mode must be shared or exclusive"
        );
        ensure!(
            self.pids_max >= 8 && self.pids_max <= 65536,
            "pids_max must be 8..65536"
        );
        let mut gpus = self.gpus.clone();
        gpus.sort_unstable();
        gpus.dedup();
        ensure!(gpus.len() == self.gpus.len(), "duplicate GPU indices");
        ensure!(
            self.env.keys().all(|k| !k.contains(['=', '\0'])),
            "invalid environment key"
        );
        for m in &self.mounts {
            ensure!(
                m.source.is_absolute() && m.source.is_dir(),
                "mount source must be an existing absolute directory"
            );
            ensure!(
                m.target.is_absolute()
                    && m.target.components().count() > 1
                    && !m
                        .target
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir)),
                "invalid mount target"
            );
            ensure!(
                !["/proc", "/dev", "/sys"]
                    .iter()
                    .any(|p| m.target.starts_with(p)),
                "mount target overlaps a reserved system directory"
            );
        }
        Ok(())
    }
}

pub fn valid_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 48
        || !id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        bail!("id must contain 1..48 ASCII letters, digits, '-' or '_'");
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub spec: Spec,
    pub uid: u32,
    pub created_at: u64,
    #[serde(default)]
    pub gpu_uuids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Status {
    pub state: String,
    pub supervisor_pid: i32,
    pub supervisor_start: u64,
    pub init_pid: i32,
    pub init_start: u64,
    pub memory_current: u64,
    pub memory_peak: u64,
    pub process_count: usize,
    pub reason: Option<String>,
    pub proc_mounted: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Exec {
        argv: Vec<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
        #[serde(default = "cwd_default")]
        cwd: String,
        #[serde(default = "timeout_default")]
        timeout: u64,
        #[serde(default = "root_user")]
        user: String,
    },
    Write {
        path: String,
        data: String,
        #[serde(default)]
        append: bool,
    },
    Read {
        path: String,
    },
    Ping,
}
fn cwd_default() -> String {
    "/workspace".into()
}
fn root_user() -> String {
    "root".into()
}
fn timeout_default() -> u64 {
    120
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identifiers_cannot_escape_state_directory() {
        for s in ["", "..", "a/b", "a\nb", "./x", "a b"] {
            assert!(valid_id(s).is_err());
        }
        assert!(valid_id("run-32_1").is_ok());
    }
    #[test]
    fn reject_invalid_admission_configuration() {
        let mut c = NodeConfig {
            memory_overcommit: f64::NAN,
            ..Default::default()
        };
        assert!(c.validate().is_err());
        c.memory_overcommit = 2.0;
        assert!(c.validate().is_ok());
        c.uid_start = 0;
        assert!(c.validate().is_err());
    }
}
