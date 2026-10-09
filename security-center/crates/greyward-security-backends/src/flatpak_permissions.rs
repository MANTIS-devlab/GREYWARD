//! Read-only normalization of Flatpak's serialized effective context.
//! No override mutation, portal capability claim or mandatory-policy evidence.
use crate::FlatpakAvailability;
use std::collections::BTreeSet;

pub(crate) fn permission_records(bytes: &[u8]) -> Result<Vec<String>, FlatpakAvailability> {
    if bytes.len() > 256 * 1024 {
        return Err(FlatpakAvailability::Partial);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| FlatpakAvailability::Partial)?;
    if text.contains('\0') {
        return Err(FlatpakAvailability::Partial);
    }
    let mut selected = false;
    let mut section = "";
    let mut keys = BTreeSet::new();
    let mut records = Vec::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        if line.starts_with('[') && line.ends_with(']') {
            section = &line[1..line.len() - 1];
            selected = matches!(
                section,
                "Context" | "Session Bus Policy" | "System Bus Policy"
            );
            if selected {
                records.push(line.to_owned());
            }
        } else if selected {
            let (key, value) = line.split_once('=').ok_or(FlatpakAvailability::Partial)?;
            // We do not guess GLib escaped-list semantics. Unsupported output
            // remains partial instead of silently dropping a path permission.
            if key.is_empty() || value.contains('\\') || !keys.insert((section, key)) {
                return Err(FlatpakAvailability::Partial);
            }
            records.push(line.to_owned());
        }
        if records.len() > 1024 {
            return Err(FlatpakAvailability::Partial);
        }
    }
    // Environment/command metadata is intentionally excluded, including values
    // that may contain credentials. This projection concerns access only.
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write;

    #[test]
    fn access_projection_never_copies_environment_values() {
        let records = permission_records(b"[Context]\nfilesystems=home;\n[Environment]\nTOKEN=synthetic-private-value\n[Session Bus Policy]\norg.example.Service=none\n").unwrap();
        assert_eq!(
            records,
            [
                "[Context]",
                "filesystems=home;",
                "[Session Bus Policy]",
                "org.example.Service=none"
            ]
        );
        assert!(!records.join("\n").contains("synthetic-private-value"));
    }

    #[test]
    fn malformed_escaped_or_excessive_context_is_not_silently_truncated() {
        for text in [
            "[Context]\nfilesystems=/tmp/a\\;b;",
            "[Context]\ninvalid",
            "[Context]\nfilesystems=home;\nfilesystems=!home;",
        ] {
            assert_eq!(
                permission_records(text.as_bytes()),
                Err(FlatpakAvailability::Partial)
            );
        }
        assert_eq!(
            permission_records(&vec![b'a'; 256 * 1024 + 1]),
            Err(FlatpakAvailability::Partial)
        );
        assert_eq!(
            permission_records(&[0xff]),
            Err(FlatpakAvailability::Partial)
        );
        let mut many = String::from("[Session Bus Policy]\n");
        for index in 0..1025 {
            writeln!(many, "org.example.Item{index}=talk").unwrap();
        }
        assert_eq!(
            permission_records(many.as_bytes()),
            Err(FlatpakAvailability::Partial)
        );
    }
}
