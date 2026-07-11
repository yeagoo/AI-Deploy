use std::{
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

const MAX_ENV_FILE_BYTES: u64 = 64 * 1024;
const DEFAULT_ENV_FILES: [&str; 2] = ["/etc/opsctl/backup.env", "/etc/opsctl/restic.env"];

pub fn var_os(name: &str) -> Option<OsString> {
    env::var_os(name).or_else(|| file_var_os(name))
}

pub fn var_string(name: &str) -> Option<String> {
    var_os(name).and_then(|value| value.into_string().ok())
}

pub fn var_source(name: &str) -> Option<String> {
    if !valid_env_name(name) {
        return None;
    }
    if env::var_os(name).is_some() {
        return Some("process".to_string());
    }
    for path in configured_file_paths() {
        let Ok(Some(_)) = read_env_file_value(&path, name) else {
            continue;
        };
        return Some(path.display().to_string());
    }
    None
}

pub fn configured_file_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for name in ["OPSCTL_ENV_FILE", "OPSCTL_BACKUP_ENV_FILE"] {
        if let Some(value) = env::var_os(name) {
            paths.extend(env::split_paths(&value));
        }
    }
    paths.extend(DEFAULT_ENV_FILES.iter().map(PathBuf::from));
    dedup_paths(paths)
}

fn file_var_os(name: &str) -> Option<OsString> {
    if !valid_env_name(name) {
        return None;
    }
    for path in configured_file_paths() {
        let Ok(Some(value)) = read_env_file_value(&path, name) else {
            continue;
        };
        return Some(OsString::from(value));
    }
    None
}

fn read_env_file_value(path: &Path, name: &str) -> Result<Option<String>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect env file {}", path.display()));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Ok(None);
    }
    if metadata.len() > MAX_ENV_FILE_BYTES {
        return Ok(None);
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read env file {}", path.display()))?;
    Ok(parse_env_file_value(&raw, name))
}

fn parse_env_file_value(raw: &str, name: &str) -> Option<String> {
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key != name || !valid_env_name(key) {
            continue;
        }
        return Some(unquote_env_value(value.trim()));
    }
    None
}

fn unquote_env_value(value: &str) -> String {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
        {
            return value[1..value.len() - 1].to_string();
        }
    }
    value.to_string()
}

fn valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_uppercase() || first == '_') {
        return false;
    }
    chars.all(|character| {
        character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_'
    })
}

fn dedup_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut deduped = Vec::new();
    for path in paths {
        if !deduped.iter().any(|existing| existing == &path) {
            deduped.push(path);
        }
    }
    deduped
}

#[cfg(test)]
mod tests {
    use super::{parse_env_file_value, valid_env_name};

    #[test]
    fn parses_env_file_values_without_shell_expansion() {
        let raw = r#"
# ignored
RESTIC_REPOSITORY="s3:https://example.invalid/bucket"
export RESTIC_PASSWORD='secret value'
AWS_ACCESS_KEY_ID=plain-key
"#;
        assert_eq!(
            parse_env_file_value(raw, "RESTIC_REPOSITORY").as_deref(),
            Some("s3:https://example.invalid/bucket")
        );
        assert_eq!(
            parse_env_file_value(raw, "RESTIC_PASSWORD").as_deref(),
            Some("secret value")
        );
        assert_eq!(
            parse_env_file_value(raw, "AWS_ACCESS_KEY_ID").as_deref(),
            Some("plain-key")
        );
    }

    #[test]
    fn rejects_invalid_env_names() {
        assert!(valid_env_name("RESTIC_PASSWORD"));
        assert!(!valid_env_name("restic_password"));
        assert!(!valid_env_name("1RESTIC_PASSWORD"));
        assert!(!valid_env_name("RESTIC-PASSWORD"));
    }
}
