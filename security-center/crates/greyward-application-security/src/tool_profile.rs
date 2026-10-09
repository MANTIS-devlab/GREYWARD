//! Root-selected, versioned launch contracts. A review is not an unrestricted
//! tool/export endpoint. New code generations require a new tested profile and
//! a fresh review; a path/name or cached Polkit authorization cannot select one.
use greyward_security_domain::ContentGeneration;
use serde::{Deserialize, Serialize};

/// This initial profile verifies that a protected SSH key is parseable. It does
/// not provide an SSH shell, signing service, IDE exception or key export.
/// Streams are discarded, including key comments and parser diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReviewedToolProfile {
    #[serde(rename = "openssh-key-inspection/v1")]
    OpenSshKeyInspectionV1,
}

impl ReviewedToolProfile {
    // Exact code tested on Fedora 44. An update cannot inherit this contract.
    // Application/package generation is independently checked by the grant.
    const SSH_KEYGEN: &'static str = "/usr/bin/ssh-keygen";
    const SSH_KEYGEN_DIGEST: &'static str =
        "bb13e6ff90ade685d2154772b6a25729e5a5a98193fdb7d6ceba53cad315a109";

    pub(crate) fn select(path: &str, generation: &ContentGeneration) -> Option<Self> {
        (path == Self::SSH_KEYGEN && generation.as_str() == Self::SSH_KEYGEN_DIGEST)
            .then_some(Self::OpenSshKeyInspectionV1)
    }

    pub(crate) fn accepts_code(self, path: &str, generation: &ContentGeneration) -> bool {
        Self::select(path, generation) == Some(self)
    }

    pub(crate) fn accepts_arguments(self, home: &str, args: &[String]) -> bool {
        // No prompts, options after a filename, expansion, arbitrary paths,
        // write modes, config/helper selection or caller-selected program.
        let [mode, flag, path] = args else {
            return false;
        };
        match self {
            Self::OpenSshKeyInspectionV1 => {
                mode == "-l"
                    && flag == "-f"
                    && ["id_ed25519", "id_rsa", "id_ecdsa"]
                        .iter()
                        .any(|name| path == &format!("{home}/.ssh/{name}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_do_not_transfer_to_another_path_or_generation() {
        let digest =
            ContentGeneration::try_from(ReviewedToolProfile::SSH_KEYGEN_DIGEST.to_owned()).unwrap();
        let changed = ContentGeneration::try_from("0".repeat(64)).unwrap();
        let profile = ReviewedToolProfile::OpenSshKeyInspectionV1;
        assert!(profile.accepts_code("/usr/bin/ssh-keygen", &digest));
        assert!(!profile.accepts_code("/usr/bin/cat", &digest));
        assert!(!profile.accepts_code("/usr/bin/ssh-keygen", &changed));
    }

    #[test]
    fn only_fixed_nonexporting_key_inspection_is_accepted() {
        let profile = ReviewedToolProfile::OpenSshKeyInspectionV1;
        let values = |items: &[&str]| items.iter().map(|v| (*v).to_owned()).collect::<Vec<_>>();
        assert!(profile.accepts_arguments(
            "/home/example",
            &values(&["-l", "-f", "/home/example/.ssh/id_ed25519"])
        ));
        for args in [
            vec!["-y", "-f", "/home/example/.ssh/id_ed25519"],
            vec!["-l", "-f", "/home/other/.ssh/id_ed25519"],
            vec!["-l", "-f", "/home/example/.ssh/../secret"],
            vec!["-l", "-f", "/home/example/.ssh/id_ed25519", "-p"],
            vec!["-Y", "sign", "-f", "/home/example/.ssh/id_ed25519"],
            vec!["-l", "-f", "/proc/self/fd/0"],
        ] {
            assert!(!profile.accepts_arguments("/home/example", &values(&args)));
        }
    }
}
