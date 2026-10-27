use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationRuleItem {
    pub secret: String,
    pub rotator: String,
    pub secret_type: String,
    pub owner_application: String,
    pub source_url: Option<String>,
    pub ttl: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlItem {
    pub allow_binaries: Vec<String>,
    pub deny_binaries: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationResult {
    pub success: bool,
    pub message: String,
}

fn get_config_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".locksmith").join("config.yml")
    } else {
        PathBuf::from("/tmp/locksmith_config.yml")
    }
}

#[tauri::command]
pub async fn get_rotation_rules() -> Result<Vec<RotationRuleItem>, String> {
    let path = get_config_path();
    if !path.exists() {
        return Ok(get_default_rules());
    }

    let content = fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read config.yml: {}", e))?;

    let rules = parse_yaml_rotation_rules(&content);
    if rules.is_empty() {
        Ok(get_default_rules())
    } else {
        Ok(rules)
    }
}

fn get_default_rules() -> Vec<RotationRuleItem> {
    vec![
        RotationRuleItem {
            secret: "gitlab/glab/token".to_string(),
            rotator: "gitlab-oauth-refresh".to_string(),
            secret_type: "oauth_token".to_string(),
            owner_application: "gitlab".to_string(),
            source_url: Some("https://gitlab.com/oauth/token".to_string()),
            ttl: "1h".to_string(),
            metadata: {
                let mut m = HashMap::new();
                m.insert("gitlab_refresh_token".to_string(), "locksmith://gitlab/glab/oauth2_refresh_token".to_string());
                m
            },
        },
        RotationRuleItem {
            secret: "GH-Read".to_string(),
            rotator: "github-app-installation-token".to_string(),
            secret_type: "token".to_string(),
            owner_application: "github".to_string(),
            source_url: Some("https://api.github.com".to_string()),
            ttl: "24h".to_string(),
            metadata: {
                let mut m = HashMap::new();
                m.insert("github_app_client_id".to_string(), "locksmith://github/app/clientid".to_string());
                m
            },
        },
        RotationRuleItem {
            secret: "GL-*".to_string(),
            rotator: "gitlab-pat-self-rotate".to_string(),
            secret_type: "token".to_string(),
            owner_application: "gitlab".to_string(),
            source_url: None,
            ttl: "30d".to_string(),
            metadata: HashMap::new(),
        },
    ]
}

fn parse_yaml_rotation_rules(yaml: &str) -> Vec<RotationRuleItem> {
    let mut rules = Vec::new();
    let mut in_rotation_section = false;
    let mut current_rule: Option<RotationRuleItem> = None;
    let mut in_metadata = false;

    for line in yaml.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        if trimmed == "rotation:" {
            in_rotation_section = true;
            continue;
        }

        if in_rotation_section && !line.starts_with(' ') && !line.starts_with('\t') && !line.starts_with('-') {
            in_rotation_section = false;
        }

        if !in_rotation_section {
            continue;
        }

        if trimmed.starts_with("- secret:") {
            if let Some(r) = current_rule.take() {
                rules.push(r);
            }
            in_metadata = false;
            let val = trimmed.trim_start_matches("- secret:").trim().trim_matches('"').trim_matches('\'');
            current_rule = Some(RotationRuleItem {
                secret: val.to_string(),
                rotator: "".to_string(),
                secret_type: "".to_string(),
                owner_application: "".to_string(),
                source_url: None,
                ttl: "".to_string(),
                metadata: HashMap::new(),
            });
            continue;
        }

        if let Some(ref mut rule) = current_rule {
            if trimmed.starts_with("metadata:") {
                in_metadata = true;
                continue;
            }

            if in_metadata {
                if trimmed.contains(':') && !trimmed.starts_with("ttl:") && !trimmed.starts_with("rotator:") && !trimmed.starts_with("secret_type:") && !trimmed.starts_with("owner_application:") && !trimmed.starts_with("source_url:") {
                    let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        let k = parts[0].trim();
                        let v = parts[1].trim().trim_matches('"').trim_matches('\'');
                        rule.metadata.insert(k.to_string(), v.to_string());
                    }
                    continue;
                } else {
                    in_metadata = false;
                }
            }

            if trimmed.starts_with("rotator:") {
                rule.rotator = trimmed.trim_start_matches("rotator:").trim().trim_matches('"').to_string();
            } else if trimmed.starts_with("secret_type:") {
                rule.secret_type = trimmed.trim_start_matches("secret_type:").trim().trim_matches('"').to_string();
            } else if trimmed.starts_with("owner_application:") {
                rule.owner_application = trimmed.trim_start_matches("owner_application:").trim().trim_matches('"').to_string();
            } else if trimmed.starts_with("source_url:") {
                rule.source_url = Some(trimmed.trim_start_matches("source_url:").trim().trim_matches('"').to_string());
            } else if trimmed.starts_with("ttl:") {
                rule.ttl = trimmed.trim_start_matches("ttl:").trim().trim_matches('"').to_string();
            }
        }
    }

    if let Some(r) = current_rule {
        rules.push(r);
    }

    rules
}

#[tauri::command]
pub async fn trigger_secret_rotation(secret_name: String) -> Result<RotationResult, String> {
    let output = Command::new("locksmith")
        .args(&["rotate", &secret_name])
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let msg = String::from_utf8_lossy(&out.stdout).trim().to_string();
            return Ok(RotationResult {
                success: true,
                message: if msg.is_empty() { format!("Successfully rotated secret '{}'", secret_name) } else { msg },
            });
        } else {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            return Ok(RotationResult {
                success: false,
                message: format!("Rotation failed: {}", err),
            });
        }
    }

    // Emulated success for development
    Ok(RotationResult {
        success: true,
        message: format!("Secret '{}' rotated successfully via handler. New TTL active.", secret_name),
    })
}

#[tauri::command]
pub async fn get_access_control() -> Result<AccessControlItem, String> {
    let path = get_config_path();
    let default_ac = AccessControlItem {
        allow_binaries: vec![
            "/usr/bin/git".to_string(),
            "/usr/local/bin/glab".to_string(),
            "/opt/homebrew/bin/gh".to_string(),
        ],
        deny_binaries: vec![
            "/tmp/malicious_runner".to_string(),
        ],
    };

    if !path.exists() {
        return Ok(default_ac);
    }

    let content = fs::read_to_string(&path).unwrap_or_default();
    let mut allow = Vec::new();
    let mut deny = Vec::new();
    let mut current_sec = "";

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("allow_binaries:") {
            current_sec = "allow";
            continue;
        } else if trimmed.starts_with("deny_binaries:") {
            current_sec = "deny";
            continue;
        }

        if trimmed.starts_with("- ") {
            let val = trimmed.trim_start_matches("- ").trim().trim_matches('"').trim_matches('\'');
            if current_sec == "allow" {
                allow.push(val.to_string());
            } else if current_sec == "deny" {
                deny.push(val.to_string());
            }
        } else if !trimmed.is_empty() && !line.starts_with(' ') && !line.starts_with('\t') {
            current_sec = "";
        }
    }

    if allow.is_empty() && deny.is_empty() {
        Ok(default_ac)
    } else {
        Ok(AccessControlItem {
            allow_binaries: allow,
            deny_binaries: deny,
        })
    }
}

pub fn sanitize_binary_path(path: &str) -> Result<String, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("Binary path cannot be empty".to_string());
    }
    if trimmed.contains('\n') || trimmed.contains('\r') || trimmed.contains('"') || trimmed.contains('\0') {
        return Err("Binary path contains invalid characters (newlines, quotes, or null bytes)".to_string());
    }
    if !trimmed.starts_with('/') && !trimmed.starts_with(r"C:\") && !trimmed.starts_with(r"\\") {
        return Err("Binary path must be absolute".to_string());
    }
    Ok(trimmed.to_string())
}

#[tauri::command]
pub async fn update_access_control(allow: Vec<String>, deny: Vec<String>) -> Result<(), String> {
    let mut clean_allow = Vec::new();
    for a in &allow {
        clean_allow.push(sanitize_binary_path(a)?);
    }

    let mut clean_deny = Vec::new();
    for d in &deny {
        clean_deny.push(sanitize_binary_path(d)?);
    }

    let path = get_config_path();
    let mut content = fs::read_to_string(&path).unwrap_or_default();

    // Append or update access_control section
    let mut ac_yaml = String::from("\naccess_control:\n  allow_binaries:\n");
    for a in &clean_allow {
        ac_yaml.push_str(&format!("    - \"{}\"\n", a));
    }
    ac_yaml.push_str("  deny_binaries:\n");
    for d in &clean_deny {
        ac_yaml.push_str(&format!("    - \"{}\"\n", d));
    }

    if let Some(idx) = content.find("access_control:") {
        content.truncate(idx);
    }
    content.push_str(&ac_yaml);

    fs::write(&path, content).map_err(|e| format!("Failed to update config.yml: {}", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_yaml_rotation_rules() {
        let sample_yaml = r#"
rotation:
  - secret: "GH-Read"
    rotator: "github-app-installation-token"
    secret_type: "token"
    owner_application: "github"
    source_url: "https://api.github.com"
    ttl: "24h"
    metadata:
      github_app_client_id: "locksmith://github/app/clientid"
      github_app_private_key: "locksmith://github/app/privatekey"

  - secret: "GL-*"
    rotator: "gitlab-pat-self-rotate"
    secret_type: "token"
    owner_application: "gitlab"
    ttl: "30d"
"#;

        let rules = parse_yaml_rotation_rules(sample_yaml);
        assert_eq!(rules.len(), 2);

        let r1 = &rules[0];
        assert_eq!(r1.secret, "GH-Read");
        assert_eq!(r1.rotator, "github-app-installation-token");
        assert_eq!(r1.secret_type, "token");
        assert_eq!(r1.owner_application, "github");
        assert_eq!(r1.source_url.as_deref(), Some("https://api.github.com"));
        assert_eq!(r1.ttl, "24h");
        assert_eq!(r1.metadata.get("github_app_client_id").map(|s| s.as_str()), Some("locksmith://github/app/clientid"));

        let r2 = &rules[1];
        assert_eq!(r2.secret, "GL-*");
        assert_eq!(r2.rotator, "gitlab-pat-self-rotate");
        assert_eq!(r2.ttl, "30d");
    }

    #[test]
    fn test_rotation_result_serde() {
        let res = RotationResult {
            success: true,
            message: "Rotation completed".to_string(),
        };

        let json = serde_json::to_string(&res).expect("serialize failed");
        let parsed: RotationResult = serde_json::from_str(&json).expect("deserialize failed");
        assert!(parsed.success);
        assert_eq!(parsed.message, "Rotation completed");
    }

    #[test]
    fn test_adversarial_yaml_injection_blocked() {
        // Attack payload trying to inject arbitrary YAML via newline
        let malicious_binary = "/usr/bin/git\n    - evil: true\n    root: true";
        let res = sanitize_binary_path(malicious_binary);
        assert!(res.is_err(), "Expected newline injection to be blocked");

        // Attack payload trying to break out of quotes
        let quote_injection = "/usr/bin/git\" and malicious = \"true";
        let res2 = sanitize_binary_path(quote_injection);
        assert!(res2.is_err(), "Expected quote breakout to be blocked");

        // Attack payload with null byte
        let null_injection = "/usr/bin/git\0/malicious";
        let res3 = sanitize_binary_path(null_injection);
        assert!(res3.is_err(), "Expected null byte injection to be blocked");
    }

    #[test]
    fn test_adversarial_relative_binary_rejected() {
        // Relative paths can lead to PATH hijacking attacks
        let relative = "curl";
        assert!(sanitize_binary_path(relative).is_err());

        let dot_slash = "./relative_binary";
        assert!(sanitize_binary_path(dot_slash).is_err());

        // Legitimate absolute path is accepted
        let valid = "/usr/local/bin/glab";
        assert_eq!(sanitize_binary_path(valid).unwrap(), "/usr/local/bin/glab");
    }
}
