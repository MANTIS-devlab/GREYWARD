use std::collections::BTreeMap;

use serde::Deserialize;
use thiserror::Error;

use crate::{EvidenceValue, PostureSnapshot, SNAPSHOT_V1_SCHEMA, ScalarValue};

pub const MAX_SNAPSHOT_BYTES: usize = 1_048_576;
const MAX_DOMAINS: usize = 6;
const MAX_CHECKS: usize = 256;
const MAX_ISSUES: usize = 128;
const MAX_EVIDENCE_PER_CHECK: usize = 64;
const MAX_MAP_ENTRIES: usize = 64;
const MAX_STRING_BYTES: usize = 4_096;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SnapshotError {
    #[error("snapshot exceeds the {MAX_SNAPSHOT_BYTES}-byte input limit")]
    InputTooLarge,
    #[error("snapshot is malformed: {0}")]
    Malformed(String),
    #[error("unsupported snapshot schema: {0}")]
    UnsupportedSchema(String),
    #[error("snapshot field exceeds a structural bound: {0}")]
    Bounds(&'static str),
}

#[derive(Deserialize)]
struct SchemaProbe {
    schema: String,
}

/// Parses a bounded v1 snapshot and rejects schema, enum, and structural skew.
///
/// # Errors
///
/// Returns [`SnapshotError`] when the input is oversized, malformed, unsupported,
/// or exceeds a bounded field or collection limit.
pub fn parse_snapshot_v1(input: &[u8]) -> Result<PostureSnapshot, SnapshotError> {
    if input.len() > MAX_SNAPSHOT_BYTES {
        return Err(SnapshotError::InputTooLarge);
    }
    let probe: SchemaProbe = serde_json::from_slice(input)
        .map_err(|error| SnapshotError::Malformed(error.to_string()))?;
    if probe.schema != SNAPSHOT_V1_SCHEMA {
        return Err(SnapshotError::UnsupportedSchema(probe.schema));
    }
    let snapshot: PostureSnapshot = serde_json::from_slice(input)
        .map_err(|error| SnapshotError::Malformed(error.to_string()))?;
    validate_bounds(&snapshot)?;
    Ok(snapshot)
}

fn validate_bounds(snapshot: &PostureSnapshot) -> Result<(), SnapshotError> {
    bounded_string(&snapshot.schema)?;
    bounded_optional_string(snapshot.boot_id.as_deref())?;
    bounded_string(&snapshot.evaluator_version)?;
    bounded_string(&snapshot.policy_profile)?;
    bounded_len(snapshot.domains.len(), MAX_DOMAINS, "domains")?;
    bounded_len(snapshot.checks.len(), MAX_CHECKS, "checks")?;
    bounded_len(
        snapshot.collection_issues.len(),
        MAX_ISSUES,
        "collection issues",
    )?;

    for domain in &snapshot.domains {
        bounded_len(domain.check_ids.len(), MAX_CHECKS, "domain check IDs")?;
        for check_id in &domain.check_ids {
            bounded_string(check_id.as_str())?;
        }
    }
    for check in &snapshot.checks {
        bounded_string(check.check_id.as_str())?;
        bounded_string(&check.reason_code)?;
        bounded_message(&check.summary)?;
        bounded_message(&check.explanation)?;
        bounded_string(&check.applicability.reason_code)?;
        bounded_map(&check.applicability.facts)?;
        bounded_len(
            check.evidence.len(),
            MAX_EVIDENCE_PER_CHECK,
            "evidence per check",
        )?;
        for evidence in &check.evidence {
            bounded_string(&evidence.evidence_id)?;
            bounded_string(&evidence.source.backend_id)?;
            bounded_string(&evidence.source.interface)?;
            bounded_string(&evidence.source.object)?;
            bounded_string(&evidence.provenance.backend_version)?;
            bounded_string(&evidence.provenance.interface_version)?;
            match &evidence.value {
                EvidenceValue::Text(value) => bounded_string(value)?,
                EvidenceValue::Object(values) => bounded_map(values)?,
                EvidenceValue::Boolean(_) | EvidenceValue::Integer(_) => {}
            }
        }
        if let Some(remediation) = &check.remediation {
            bounded_string(&remediation.action_id)?;
            bounded_message(&remediation.title)?;
            bounded_message(&remediation.consequence)?;
            bounded_string(&remediation.expected_effect.predicate_id)?;
            bounded_map(&remediation.expected_effect.parameters)?;
        }
    }
    for issue in &snapshot.collection_issues {
        bounded_string(&issue.backend_id)?;
        bounded_message(&issue.safe_message)?;
    }
    Ok(())
}

fn bounded_message(message: &crate::LocalizedMessage) -> Result<(), SnapshotError> {
    bounded_string(&message.key)?;
    bounded_map(&message.parameters)
}

fn bounded_map(values: &BTreeMap<String, ScalarValue>) -> Result<(), SnapshotError> {
    bounded_len(values.len(), MAX_MAP_ENTRIES, "map entries")?;
    for (key, value) in values {
        bounded_string(key)?;
        if let ScalarValue::Text(text) = value {
            bounded_string(text)?;
        }
    }
    Ok(())
}

fn bounded_optional_string(value: Option<&str>) -> Result<(), SnapshotError> {
    value.map_or(Ok(()), bounded_string)
}

fn bounded_string(value: &str) -> Result<(), SnapshotError> {
    bounded_len(value.len(), MAX_STRING_BYTES, "string")
}

fn bounded_len(actual: usize, maximum: usize, name: &'static str) -> Result<(), SnapshotError> {
    if actual > maximum {
        Err(SnapshotError::Bounds(name))
    } else {
        Ok(())
    }
}
