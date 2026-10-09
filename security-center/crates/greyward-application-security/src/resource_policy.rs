//! Bounded deterministic resource-denial preparation for the development baseline.
//! No label installer, effective coverage, grant compiler or production enrollment.
use crate::{MAX_POLICY_RESOURCES, ResourceIntent, content_generation};
use greyward_security_domain::{ContentGeneration, SecurityReference};
use std::collections::BTreeMap;
use std::fmt::Write;
use thiserror::Error;

const PROBE_SUBJECT: &str = "greyward_guard_t";
const MAX_PROGRAM_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const FILE_DENIALS: &[&str] = &[
    "open",
    "read",
    "write",
    "append",
    "execute",
    "execute_no_trans",
    "create",
    "rename",
    "unlink",
    "link",
    "relabelfrom",
    "relabelto",
    "setattr",
];
pub(crate) const DIRECTORY_DENIALS: &[&str] = &[
    "open",
    "read",
    "write",
    "add_name",
    "remove_name",
    "create",
    "rmdir",
    "rename",
    "reparent",
    "relabelfrom",
    "relabelto",
    "setattr",
];
pub(crate) const SYMLINK_DENIALS: &[&str] = &[
    "read",
    "write",
    "append",
    "create",
    "rename",
    "unlink",
    "link",
    "relabelfrom",
    "relabelto",
    "setattr",
];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ResourcePolicyError {
    #[error("Invalid or stale resource policy revision")]
    Revision,
    #[error("Resource policy has foreign, conflicting or invalid intentions")]
    InvalidResource,
    #[error("Resource policy exceeds its bounded representation")]
    Capacity,
}

/// An uninstalled CIL program. Its digest is a cache key, not authenticity or
/// evidence that descriptors, resource labels or session domains were established.
pub struct ResourceDenialProgram {
    revision: u64,
    owner_uid: u32,
    labels: BTreeMap<SecurityReference, String>,
    cil: String,
    generation: ContentGeneration,
}

impl ResourceDenialProgram {
    /// The only supported baseline is the reviewed separate-account probe.
    /// The production domain/package and grant transitions remain separate gates.
    /// No caller-defined subjects, policy snippets, labels or pathnames are accepted.
    /// # Errors
    /// Invalid revisions, conflicting/foreign records and unbounded input refuse.
    pub fn prepare_development_baseline(
        expected_revision: u64,
        revision: u64,
        owner_uid: u32,
        resources: &[ResourceIntent],
    ) -> Result<Self, ResourcePolicyError> {
        Self::prepare_for_subject(
            expected_revision,
            revision,
            owner_uid,
            resources,
            PROBE_SUBJECT,
        )
    }

    pub(crate) fn prepare_bound(
        binding: &crate::enrollment::ProviderBinding,
        expected_revision: u64,
        revision: u64,
        resources: &[ResourceIntent],
    ) -> Result<Self, ResourcePolicyError> {
        Self::prepare_for_subject(
            expected_revision,
            revision,
            binding.uid,
            resources,
            if binding.production {
                "greyward_as_ordinary"
            } else {
                PROBE_SUBJECT
            },
        )
    }

    fn prepare_for_subject(
        expected_revision: u64,
        revision: u64,
        owner_uid: u32,
        resources: &[ResourceIntent],
        subject: &str,
    ) -> Result<Self, ResourcePolicyError> {
        if expected_revision == 0 || expected_revision != revision {
            return Err(ResourcePolicyError::Revision);
        }
        if resources.len() > MAX_POLICY_RESOURCES {
            return Err(ResourcePolicyError::Capacity);
        }
        let mut labels = BTreeMap::new();
        for record in resources {
            if !record.validate(revision) || record.resource().owner_uid != owner_uid {
                return Err(ResourcePolicyError::InvalidResource);
            }
            let reference = &record.resource().resource_ref;
            let digest = reference
                .as_str()
                .strip_prefix("resource_")
                .ok_or(ResourcePolicyError::InvalidResource)?;
            let label = format!("greyward_as_resource_{digest}_t");
            if labels.insert(reference.clone(), label).is_some() {
                return Err(ResourcePolicyError::InvalidResource);
            }
        }
        let mut cil = format!("; greyward.resource-denial/v1 revision={revision}\n");
        for label in labels.values() {
            // File attributes match Fedora's files_auth_file interface; no
            // ordinary home/non-auth attribute or resource read allow is added.
            writeln!(cil, "(type {label})").expect("String formatting");
            for attribute in ["file_type", "security_file_type", "auth_file_type"] {
                writeln!(cil, "(typeattributeset {attribute} ({label}))")
                    .expect("String formatting");
            }
            writeln!(cil, "(roletype object_r {label})").expect("String formatting");
            writeln!(cil, "(allow {subject} {label} (dir (search getattr)))")
                .expect("String formatting");
            writeln!(cil, "(allow {subject} {label} (file (getattr)))").expect("String formatting");
            // Fedora domain_can_mmap_files allows map alone across file_type.
            // Linux mmap additionally checks read (including PROT_NONE). Keep
            // the decisive read/open assertion; verify held-FD mmap on the kernel.
            for (class, rights) in [
                ("file", FILE_DENIALS),
                ("dir", DIRECTORY_DENIALS),
                ("lnk_file", SYMLINK_DENIALS),
            ] {
                if subject == "greyward_as_ordinary" {
                    // Fedora helpers may inherit auth_file_type access. Remove
                    // that access from the entire admitted ordinary role before
                    // asserting the mandatory deny, rather than trusting the
                    // main application domain alone.
                    writeln!(
                        cil,
                        "(deny {subject} {label} ({class} ({})))",
                        rights.join(" ")
                    )
                    .expect("String formatting");
                    writeln!(
                        cil,
                        "(deny greyward_as_display_t {label} ({class} ({})))",
                        rights.join(" ")
                    )
                    .expect("String formatting");
                }
                writeln!(
                    cil,
                    "(neverallow {subject} {label} ({class} ({})))",
                    rights.join(" ")
                )
                .expect("String formatting");
            }
        }
        if cil.len() > MAX_PROGRAM_BYTES {
            return Err(ResourcePolicyError::Capacity);
        }
        let generation = content_generation(cil.as_bytes());
        Ok(Self {
            revision,
            owner_uid,
            labels,
            cil,
            generation,
        })
    }

    pub(crate) fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn cil(&self) -> &str {
        &self.cil
    }
    pub fn generation(&self) -> &ContentGeneration {
        &self.generation
    }
    pub fn resource_label(&self, reference: &SecurityReference) -> Option<&str> {
        self.labels.get(reference).map(String::as_str)
    }
    pub(crate) fn reference_for_label(&self, label: &str) -> Option<&SecurityReference> {
        self.labels
            .iter()
            .find_map(|(reference, value)| (value == label).then_some(reference))
    }
    pub(crate) fn labels(&self) -> impl Iterator<Item = &str> {
        self.labels.values().map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resource(number: u64, label: &str) -> ResourceIntent {
        serde_json::from_value(serde_json::json!({
            "resource": {"resource_ref": format!("resource_{number:064x}"), "owner_uid": 1002,
                "category": "CUSTOM", "label": label, "coverage": "UNKNOWN", "policy_revision": 2},
            "object": {"device": 1, "inode": number, "owner_uid": 1002,
                "changed_seconds": 1, "changed_nanoseconds": 0},
            "reviewed_by": {"execution_ref": format!("execution_{:064x}", 1),
                "installation_ref": null, "owner_uid": 1002,
                "boot_id": "12345678-1234-1234-1234-123456789abc",
                "pid": 42, "start_ticks": 100, "selinux_context": "user_u:user_r:user_t:s0"},
            "operation_ref": format!("operation_{number:064x}")
        }))
        .unwrap()
    }

    #[test]
    fn canonical_program_is_independent_of_display_text_and_input_order() {
        let first = resource(1, "Private category");
        let second = resource(2, "ordinary label");
        let program = ResourceDenialProgram::prepare_development_baseline(
            2,
            2,
            1002,
            &[first.clone(), second.clone()],
        )
        .unwrap();
        let changed_label = resource(1, "); (allow attacker secret (file (read)))");
        let reordered = ResourceDenialProgram::prepare_development_baseline(
            2,
            2,
            1002,
            &[second, changed_label],
        )
        .unwrap();
        assert_eq!(program.generation(), reordered.generation());
        assert_eq!(program.cil(), reordered.cil());
        assert!(!program.cil().contains("attacker"));
        assert!(
            program
                .resource_label(&first.resource().resource_ref)
                .is_some()
        );
        let next =
            ResourceDenialProgram::prepare_development_baseline(3, 3, 1002, &[first]).unwrap();
        assert_ne!(program.generation(), next.generation());
    }

    #[test]
    fn stale_foreign_false_protection_or_duplicate_records_cannot_compile() {
        let first = resource(1, "Synthetic");
        assert!(matches!(
            ResourceDenialProgram::prepare_development_baseline(
                1,
                2,
                1002,
                std::slice::from_ref(&first)
            ),
            Err(ResourcePolicyError::Revision)
        ));
        assert!(
            ResourceDenialProgram::prepare_development_baseline(
                2,
                2,
                1001,
                std::slice::from_ref(&first)
            )
            .is_err()
        );
        assert!(
            ResourceDenialProgram::prepare_development_baseline(
                2,
                2,
                1002,
                &[first.clone(), first.clone()]
            )
            .is_err()
        );
        let mut false_protection = first;
        false_protection.resource.coverage = greyward_security_domain::ResourceCoverage::Protected;
        assert!(
            ResourceDenialProgram::prepare_development_baseline(2, 2, 1002, &[false_protection])
                .is_err()
        );
    }

    #[test]
    fn policy_preparation_has_a_two_thousand_resource_bound() {
        let resources: Vec<_> = (1..=2000)
            .map(|number| resource(number, "Synthetic"))
            .collect();
        let program =
            ResourceDenialProgram::prepare_development_baseline(2, 2, 1002, &resources).unwrap();
        assert!(program.cil().len() < MAX_PROGRAM_BYTES);
        let mut oversized = resources;
        oversized.push(resource(2001, "Synthetic"));
        assert!(matches!(
            ResourceDenialProgram::prepare_development_baseline(2, 2, 1002, &oversized),
            Err(ResourcePolicyError::Capacity)
        ));
    }
}
