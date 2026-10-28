use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use super::binary::find_locksmith_binary;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretItem {
    pub key: String,
    pub secret_type: String,
    pub owner_application: String,
    pub source_url: String,
    pub created_at: String,
    pub expires_at: String,
    pub status: String, // "StatusValid", "StatusExpiring", "StatusExpired"
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricRevealResponse {
    pub success: bool,
    pub value: Option<String>,
    pub error: Option<String>,
}

#[tauri::command]
pub async fn get_vault_secrets() -> Result<Vec<SecretItem>, String> {
    let bin = find_locksmith_binary();
    let output = Command::new(&bin)
        .args(&["list", "--details"])
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let parsed = parse_locksmith_list_details(&stdout);
            return Ok(parsed);
        } else {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            if !stderr.is_empty() {
                return Err(format!("locksmith list error: {}", stderr));
            }
        }
    }

    Ok(vec![])
}

fn parse_locksmith_list_details(output: &str) -> Vec<SecretItem> {
    let mut items = Vec::new();
    let mut current: Option<SecretItem> = None;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Key:") {
            if let Some(item) = current.take() {
                items.push(item);
            }
            let key = trimmed.trim_start_matches("Key:").trim().to_string();
            current = Some(SecretItem {
                key,
                secret_type: "unspecified".to_string(),
                owner_application: "".to_string(),
                source_url: "".to_string(),
                created_at: "".to_string(),
                expires_at: "".to_string(),
                status: "StatusValid".to_string(),
                metadata: HashMap::new(),
            });
        } else if let Some(ref mut item) = current {
            if trimmed.starts_with("Status:") {
                let s = trimmed.trim_start_matches("Status:").trim().to_lowercase();
                item.status = match s.as_str() {
                    "expired" => "StatusExpired".to_string(),
                    "expiring" => "StatusExpiring".to_string(),
                    _ => "StatusValid".to_string(),
                };
            } else if trimmed.starts_with("Created:") {
                item.created_at = trimmed.trim_start_matches("Created:").trim().to_string();
            } else if trimmed.starts_with("Expires:") {
                item.expires_at = trimmed.trim_start_matches("Expires:").trim().to_string();
            } else if trimmed.starts_with("Type:") {
                item.secret_type = trimmed.trim_start_matches("Type:").trim().to_string();
            } else if trimmed.starts_with("Owner App:") {
                item.owner_application = trimmed.trim_start_matches("Owner App:").trim().to_string();
            } else if trimmed.starts_with("Source URL:") {
                item.source_url = trimmed.trim_start_matches("Source URL:").trim().to_string();
            } else if trimmed.contains(':') && !trimmed.starts_with("Metadata:") {
                let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
                if parts.len() == 2 {
                    item.metadata.insert(parts[0].trim().to_string(), parts[1].trim().to_string());
                }
            }
        }
    }

    if let Some(item) = current {
        items.push(item);
    }

    items
}

pub fn sanitize_secret_key(key: &str) -> Result<String, String> {
    let trimmed = key.trim();
    if trimmed.is_empty() {
        return Err("Secret key cannot be empty".to_string());
    }
    if trimmed.starts_with('-') {
        return Err("Secret key cannot start with a dash".to_string());
    }
    if trimmed.contains('\0') || trimmed.contains('\n') || trimmed.contains('\r') {
        return Err("Secret key contains invalid control characters".to_string());
    }
    if trimmed.contains("..") {
        return Err("Secret key cannot contain path traversal sequences".to_string());
    }
    Ok(trimmed.to_string())
}

#[tauri::command]
pub async fn reveal_secret_biometric(key: String) -> Result<BiometricRevealResponse, String> {
    let safe_key = sanitize_secret_key(&key)?;
    let bin = find_locksmith_binary();

    // Biometric read via `locksmith get <key>`
    let output = Command::new(&bin)
        .args(&["get", &safe_key])
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let secret_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
            return Ok(BiometricRevealResponse {
                success: true,
                value: Some(secret_str),
                error: None,
            });
        } else {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            return Ok(BiometricRevealResponse {
                success: false,
                value: None,
                error: Some(if err.is_empty() { "Failed to retrieve secret".to_string() } else { err }),
            });
        }
    }

    Ok(BiometricRevealResponse {
        success: false,
        value: None,
        error: Some(format!("Could not execute locksmith binary at {:?}", bin)),
    })
}

#[tauri::command]
pub async fn delete_vault_secret(key: String) -> Result<bool, String> {
    let safe_key = sanitize_secret_key(&key)?;
    let bin = find_locksmith_binary();
    let output = Command::new(&bin)
        .args(&["delete", &safe_key])
        .output();

    match output {
        Ok(out) => Ok(out.status.success()),
        Err(e) => Err(format!("Failed to execute delete: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_locksmith_list_details() {
        let sample_output = r#"
Key:        github/pat/primary
Status:     valid
Created:    2026-10-01T12:00:00Z
Expires:    2026-11-01T12:00:00Z
Type:       token
Owner App:  github
Source URL: https://api.github.com
Metadata:
  scope: repo,read:org
  client_id: 12345

Key:        legacy/test
Status:     expired
Created:    2026-01-01T00:00:00Z
Expires:    2026-02-01T00:00:00Z
Type:       password
Owner App:  internal
Source URL: N/A
Metadata:
  (none)
"#;

        let parsed = parse_locksmith_list_details(sample_output);
        assert_eq!(parsed.len(), 2);

        let item1 = &parsed[0];
        assert_eq!(item1.key, "github/pat/primary");
        assert_eq!(item1.status, "StatusValid");
        assert_eq!(item1.secret_type, "token");
        assert_eq!(item1.owner_application, "github");
        assert_eq!(item1.source_url, "https://api.github.com");
        assert_eq!(item1.metadata.get("scope").map(|s| s.as_str()), Some("repo,read:org"));
        assert_eq!(item1.metadata.get("client_id").map(|s| s.as_str()), Some("12345"));

        let item2 = &parsed[1];
        assert_eq!(item2.key, "legacy/test");
        assert_eq!(item2.status, "StatusExpired");
        assert_eq!(item2.secret_type, "password");
    }

    #[test]
    fn test_biometric_reveal_response_serde() {
        let resp = BiometricRevealResponse {
            success: true,
            value: Some("glpat-secret-token".to_string()),
            error: None,
        };

        let json = serde_json::to_string(&resp).expect("serialize failed");
        let parsed: BiometricRevealResponse = serde_json::from_str(&json).expect("deserialize failed");

        assert!(parsed.success);
        assert_eq!(parsed.value.as_deref(), Some("glpat-secret-token"));
        assert!(parsed.error.is_none());
    }

    #[test]
    fn test_adversarial_secret_key_sanitization() {
        // Path traversal attempts
        assert!(sanitize_secret_key("../../etc/shadow").is_err());
        assert!(sanitize_secret_key("keys/../../../secret").is_err());

        // Control characters & null bytes
        assert!(sanitize_secret_key("key\0injected").is_err());
        assert!(sanitize_secret_key("key\ninjected").is_err());
        assert!(sanitize_secret_key("   ").is_err());

        // Flag injection attempts
        assert!(sanitize_secret_key("--dangerous-flag").is_err());
        assert!(sanitize_secret_key("-rf").is_err());

        // Valid hierarchical keys
        assert_eq!(sanitize_secret_key("gitlab/glab/token").unwrap(), "gitlab/glab/token");
        assert_eq!(sanitize_secret_key("GH-Read").unwrap(), "GH-Read");
    }
}
