use std::{
    env,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct RuntimePaths {
    pub registry_dir: PathBuf,
    pub state_dir: PathBuf,
    pub state_db: PathBuf,
    pub audit_log: PathBuf,
}

impl RuntimePaths {
    pub fn resolve(registry_arg: Option<PathBuf>, state_dir_arg: Option<PathBuf>) -> Result<Self> {
        let registry_dir = match registry_arg {
            Some(path) => path,
            None => default_registry_dir()?,
        };

        let state_dir = match state_dir_arg {
            Some(path) => path,
            None => default_state_dir()?,
        };

        Ok(Self {
            state_db: state_dir.join("opsctl.db"),
            audit_log: state_dir.join("audit.log"),
            registry_dir,
            state_dir,
        })
    }
}

fn default_registry_dir() -> Result<PathBuf> {
    if let Ok(value) = env::var("OPSCTL_REGISTRY") {
        return Ok(PathBuf::from(value));
    }

    let current_dir = env::current_dir().context("failed to read current directory")?;
    let example_registry = current_dir.join("examples/server-registry");
    if example_registry.exists() {
        return Ok(example_registry);
    }

    Ok(PathBuf::from("/srv/server-registry"))
}

fn default_state_dir() -> Result<PathBuf> {
    if let Ok(value) = env::var("OPSCTL_STATE_DIR") {
        return Ok(PathBuf::from(value));
    }

    let current_dir = env::current_dir().context("failed to read current directory")?;
    Ok(current_dir.join(".opsctl"))
}

pub fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
