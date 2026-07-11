use serde_json::{Map, Value};

const REDACTED: &str = "[REDACTED]";

pub fn redact_value(value: &Value) -> Value {
    match value {
        Value::Object(object) => redact_object(object),
        Value::Array(items) => Value::Array(items.iter().map(redact_value).collect()),
        Value::String(text) if looks_like_inline_secret(text) => {
            Value::String(REDACTED.to_string())
        }
        other => other.clone(),
    }
}

fn redact_object(object: &Map<String, Value>) -> Value {
    let mut redacted = Map::new();
    for (key, value) in object {
        let value = if is_sensitive_key(key) {
            Value::String(REDACTED.to_string())
        } else {
            redact_value(value)
        };
        redacted.insert(key.clone(), value);
    }
    Value::Object(redacted)
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();

    [
        "password",
        "passwd",
        "secret",
        "token",
        "apikey",
        "accesstoken",
        "refreshtoken",
        "privatekey",
        "credential",
        "authorization",
        "cookie",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

fn looks_like_inline_secret(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let has_assignment = lower.contains('=') || lower.contains(':');
    has_assignment
        && [
            "password",
            "passwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "authorization",
            "cookie",
            "private_key",
        ]
        .iter()
        .any(|marker| lower.contains(marker))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::redact_value;

    #[test]
    fn redacts_sensitive_object_values() {
        let value = json!({
            "database_password": "do-not-print",
            "nested": {
                "apiToken": "also-secret",
                "safe": "visible"
            }
        });

        let redacted = redact_value(&value);

        assert_eq!(redacted["database_password"], "[REDACTED]");
        assert_eq!(redacted["nested"]["apiToken"], "[REDACTED]");
        assert_eq!(redacted["nested"]["safe"], "visible");
    }

    #[test]
    fn redacts_inline_secret_assignments_but_keeps_key_names() {
        let value = json!({
            "env_keys": ["SECRET_TOKEN", "PORT"],
            "line": "SECRET_TOKEN=do-not-print"
        });

        let redacted = redact_value(&value);

        assert_eq!(redacted["env_keys"][0], "SECRET_TOKEN");
        assert_eq!(redacted["line"], "[REDACTED]");
    }
}
