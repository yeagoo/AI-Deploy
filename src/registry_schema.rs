use std::{fs, path::Path};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy)]
pub struct SchemaDefinition {
    pub name: &'static str,
    pub file_name: &'static str,
    pub raw_yaml: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct SchemaListItem {
    pub name: &'static str,
    pub file_name: &'static str,
    pub id: Option<String>,
    pub title: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SchemaValidationReport {
    pub ok: bool,
    pub files_checked: usize,
    pub errors: usize,
    pub findings: Vec<SchemaValidationFinding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SchemaValidationFinding {
    pub file: String,
    pub schema: String,
    pub instance_path: String,
    pub schema_path: String,
    pub message: String,
}

pub const SCHEMAS: &[SchemaDefinition] = &[
    SchemaDefinition {
        name: "services",
        file_name: "services.schema.yml",
        raw_yaml: include_str!("../schemas/services.schema.yml"),
    },
    SchemaDefinition {
        name: "ports",
        file_name: "ports.schema.yml",
        raw_yaml: include_str!("../schemas/ports.schema.yml"),
    },
    SchemaDefinition {
        name: "domains",
        file_name: "domains.schema.yml",
        raw_yaml: include_str!("../schemas/domains.schema.yml"),
    },
    SchemaDefinition {
        name: "volumes",
        file_name: "volumes.schema.yml",
        raw_yaml: include_str!("../schemas/volumes.schema.yml"),
    },
    SchemaDefinition {
        name: "snapshots",
        file_name: "snapshots.schema.yml",
        raw_yaml: include_str!("../schemas/snapshots.schema.yml"),
    },
    SchemaDefinition {
        name: "backups",
        file_name: "backups.schema.yml",
        raw_yaml: include_str!("../schemas/backups.schema.yml"),
    },
    SchemaDefinition {
        name: "policies",
        file_name: "policies.schema.yml",
        raw_yaml: include_str!("../schemas/policies.schema.yml"),
    },
    SchemaDefinition {
        name: "plans",
        file_name: "plans.schema.yml",
        raw_yaml: include_str!("../schemas/plans.schema.yml"),
    },
    SchemaDefinition {
        name: "approvals",
        file_name: "approvals.schema.yml",
        raw_yaml: include_str!("../schemas/approvals.schema.yml"),
    },
    SchemaDefinition {
        name: "retention-attestation",
        file_name: "retention-attestation.schema.yml",
        raw_yaml: include_str!("../schemas/retention-attestation.schema.yml"),
    },
];

pub const REGISTRY_SCHEMA_FILES: &[(&str, &str)] = &[
    ("services.yml", "services"),
    ("ports.yml", "ports"),
    ("domains.yml", "domains"),
    ("volumes.yml", "volumes"),
    ("snapshots.yml", "snapshots"),
    ("backups.yml", "backups"),
    ("policies.yml", "policies"),
];

pub fn list_schemas() -> Result<Vec<SchemaListItem>> {
    SCHEMAS
        .iter()
        .map(|schema| {
            let value = schema_as_json(schema.name)?;
            Ok(SchemaListItem {
                name: schema.name,
                file_name: schema.file_name,
                id: string_field(&value, "$id"),
                title: string_field(&value, "title"),
            })
        })
        .collect()
}

pub fn schema_by_name(name: &str) -> Result<&'static SchemaDefinition> {
    validate_schema_name(name)?;
    SCHEMAS
        .iter()
        .find(|schema| schema.name == name)
        .context("schema not found")
}

pub fn schema_as_json(name: &str) -> Result<Value> {
    let schema = schema_by_name(name)?;
    serde_yaml::from_str::<Value>(schema.raw_yaml)
        .with_context(|| format!("failed to parse embedded schema {}", schema.file_name))
}

pub fn validate_registry_schemas(root: &Path) -> SchemaValidationReport {
    let mut findings = Vec::new();
    let mut files_checked = 0;

    if !root.exists() {
        findings.push(SchemaValidationFinding {
            file: String::new(),
            schema: "registry".to_string(),
            instance_path: String::new(),
            schema_path: String::new(),
            message: format!("registry directory does not exist: {}", root.display()),
        });
        return SchemaValidationReport {
            ok: false,
            files_checked,
            errors: findings.len(),
            findings,
        };
    }
    if !root.is_dir() {
        findings.push(SchemaValidationFinding {
            file: String::new(),
            schema: "registry".to_string(),
            instance_path: String::new(),
            schema_path: String::new(),
            message: format!("registry path is not a directory: {}", root.display()),
        });
        return SchemaValidationReport {
            ok: false,
            files_checked,
            errors: findings.len(),
            findings,
        };
    }

    for (file_name, schema_name) in REGISTRY_SCHEMA_FILES {
        files_checked += 1;
        validate_yaml_file(root, file_name, schema_name, &mut findings);
    }

    SchemaValidationReport {
        ok: findings.is_empty(),
        files_checked,
        errors: findings.len(),
        findings,
    }
}

fn validate_yaml_file(
    root: &Path,
    file_name: &str,
    schema_name: &str,
    findings: &mut Vec<SchemaValidationFinding>,
) {
    let path = root.join(file_name);
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) => {
            findings.push(SchemaValidationFinding {
                file: file_name.to_string(),
                schema: schema_name.to_string(),
                instance_path: String::new(),
                schema_path: String::new(),
                message: format!("failed to read registry file {}: {error}", path.display()),
            });
            return;
        }
    };

    let instance = match serde_yaml::from_str::<Value>(&raw) {
        Ok(instance) => instance,
        Err(error) => {
            findings.push(SchemaValidationFinding {
                file: file_name.to_string(),
                schema: schema_name.to_string(),
                instance_path: String::new(),
                schema_path: String::new(),
                message: format!("failed to parse registry file {}: {error}", path.display()),
            });
            return;
        }
    };

    let schema = match schema_as_json(schema_name) {
        Ok(schema) => schema,
        Err(error) => {
            findings.push(SchemaValidationFinding {
                file: file_name.to_string(),
                schema: schema_name.to_string(),
                instance_path: String::new(),
                schema_path: String::new(),
                message: format!("failed to load embedded schema {schema_name}: {error}"),
            });
            return;
        }
    };

    let validator = match jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
    {
        Ok(validator) => validator,
        Err(error) => {
            findings.push(SchemaValidationFinding {
                file: file_name.to_string(),
                schema: schema_name.to_string(),
                instance_path: String::new(),
                schema_path: String::new(),
                message: format!("failed to compile embedded schema {schema_name}: {error}"),
            });
            return;
        }
    };

    findings.extend(
        validator
            .iter_errors(&instance)
            .map(|error| SchemaValidationFinding {
                file: file_name.to_string(),
                schema: schema_name.to_string(),
                instance_path: error.instance_path().to_string(),
                schema_path: error.schema_path().to_string(),
                message: error.to_string(),
            }),
    );
}

fn validate_schema_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        anyhow::bail!("invalid schema name");
    }
    if name.chars().any(|character| {
        !(character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-')
    }) {
        anyhow::bail!("invalid schema name");
    }
    Ok(())
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use tempfile::TempDir;

    use super::{list_schemas, schema_as_json, schema_by_name, validate_registry_schemas};

    #[test]
    fn lists_embedded_schemas() -> Result<()> {
        let schemas = list_schemas()?;

        assert!(schemas.iter().any(|schema| schema.name == "services"));
        assert!(schemas.iter().any(|schema| schema.name == "plans"));
        assert!(schemas.iter().any(|schema| schema.name == "policies"));
        Ok(())
    }

    #[test]
    fn exports_schema_as_json_value() -> Result<()> {
        let schema = schema_as_json("services")?;

        assert_eq!(schema["title"], "opsctl services registry");
        assert_eq!(schema["type"], "object");
        Ok(())
    }

    #[test]
    fn rejects_unsafe_schema_name() -> Result<()> {
        let error = match schema_by_name("../services") {
            Ok(_) => anyhow::bail!("unsafe schema name should be rejected"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("invalid schema name"));
        Ok(())
    }

    #[test]
    fn validates_example_registry_against_embedded_schemas() {
        let report = validate_registry_schemas(std::path::Path::new("examples/server-registry"));

        assert!(report.ok);
        assert_eq!(report.errors, 0);
        assert_eq!(report.files_checked, 7);
    }

    #[test]
    fn reports_schema_validation_errors() -> Result<()> {
        let temp_dir = TempDir::new()?;
        copy_example_registry(temp_dir.path())?;
        std::fs::write(
            temp_dir.path().join("services.yml"),
            r#"
version: 1
services:
  - id: bad id
    name: Broken
    kind: unknown
    environment: production
    status: active
    unexpected: true
"#,
        )?;

        let report = validate_registry_schemas(temp_dir.path());

        assert!(!report.ok);
        assert!(report.errors >= 2);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.file == "services.yml"
                    && finding.instance_path.contains("/services/0"))
        );
        Ok(())
    }

    #[test]
    fn validates_policies_registry_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        copy_example_registry(temp_dir.path())?;
        std::fs::write(
            temp_dir.path().join("policies.yml"),
            r#"
version: 1
defaults:
  production_requires_snapshot: "yes"
protected_paths:
  - relative/path
blocked_commands: []
dangerous_operations:
  - unknown_operation
redaction_patterns: []
"#,
        )?;

        let report = validate_registry_schemas(temp_dir.path());

        assert!(!report.ok);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| { finding.file == "policies.yml" && finding.schema == "policies" })
        );
        Ok(())
    }

    fn copy_example_registry(target: &std::path::Path) -> Result<()> {
        for file_name in [
            "services.yml",
            "ports.yml",
            "domains.yml",
            "volumes.yml",
            "snapshots.yml",
            "backups.yml",
            "policies.yml",
        ] {
            std::fs::copy(
                std::path::Path::new("examples/server-registry").join(file_name),
                target.join(file_name),
            )?;
        }
        Ok(())
    }
}
