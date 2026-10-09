//! Strict provider metadata. Deployment commits are identity, not provenance.
use greyward_security_domain::ContentGeneration;
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstalledFlatpak {
    pub application_id: String,
    pub name: Option<String>,
    pub version: Option<String>,
    pub origin: Option<String>,
    pub arch: String,
    pub branch: String,
    pub runtime: Option<String>,
}

fn segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        && !value.starts_with(['-', '.'])
}

impl InstalledFlatpak {
    pub fn reference(&self) -> String {
        format!("{}/{}/{}", self.application_id, self.arch, self.branch)
    }
    fn validate(&self) -> bool {
        self.application_id.len() <= 255
            && self.application_id.split('.').count() >= 3
            && self.application_id.split('.').all(segment)
            && segment(&self.arch)
            && segment(&self.branch)
            && [&self.name, &self.version, &self.origin, &self.runtime]
                .into_iter()
                .flatten()
                .all(|value| value.len() <= 512 && !value.chars().any(char::is_control))
    }
}

pub(crate) fn installed_records(bytes: &[u8]) -> Result<Vec<InstalledFlatpak>, ()> {
    // Flatpak 1.18.4 emits no bytes for a successful empty installation even
    // with --json. The caller checks process success before this decoder.
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() > 1024 * 1024 {
        return Err(());
    }
    let records: Vec<InstalledFlatpak> = serde_json::from_slice(bytes).map_err(|_| ())?;
    if records.len() > 2000 {
        return Err(());
    }
    let mut references = BTreeSet::new();
    for record in &records {
        if !record.validate() || !references.insert(record.reference()) {
            return Err(());
        }
    }
    Ok(records)
}

pub(crate) fn deployment_commit(bytes: &[u8]) -> Result<ContentGeneration, ()> {
    if bytes.len() > 65 {
        return Err(());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ())?;
    ContentGeneration::try_from(text.strip_suffix('\n').unwrap_or(text).to_owned()).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicate_truncated_or_command_shaped_rows_are_not_a_complete_inventory() {
        let row = r#"{"application_id":"org.example.App","name":"Example","version":null,"origin":"flathub","arch":"x86_64","branch":"stable","runtime":null}"#;
        assert_eq!(
            installed_records(format!("[{row}]").as_bytes()).unwrap()[0].reference(),
            "org.example.App/x86_64/stable"
        );
        for value in [
            format!("[{row},{row}]"),
            format!("[{row}"),
            format!("[{}]", row.replace("stable", "--command=sh")),
            format!("[{}]", row.replace("x86_64", "x86_64/other")),
        ] {
            assert!(installed_records(value.as_bytes()).is_err());
        }
        assert!(installed_records(b"[]").unwrap().is_empty());
        assert!(installed_records(b"").unwrap().is_empty());
        assert!(installed_records(b" ").is_err());
    }
    #[test]
    fn only_full_canonical_deployment_commits_can_bind_a_generation() {
        let valid = format!("{}\n", "a".repeat(64));
        assert_eq!(
            deployment_commit(valid.as_bytes()).unwrap().as_str(),
            "a".repeat(64)
        );
        for invalid in [
            "a".repeat(12),
            "A".repeat(64),
            format!(" {}", "a".repeat(64)),
            format!("{}\n\n", "a".repeat(64)),
        ] {
            assert!(deployment_commit(invalid.as_bytes()).is_err());
        }
    }
}
