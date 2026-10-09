//! Validate typed Context read projections before presentation. No write APIs.
use chrono::{DateTime, Duration, Utc};
use greyward_security_domain::{
    APPLICATION_SECURITY_SCHEMA, ApplicationCoverage, ApplicationInventoryPage, ApplicationLookup,
    ApplicationReadAvailability, ApplicationReadDetails, ApplicationReadEnvelope,
    EnforcementHealth, ProtectedResource, ProtectedResourceLookup, ProtectedResourcePage,
    ProtectionSnapshot, SecurityReference,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::BTreeSet;
use thiserror::Error;

pub const MAX_APPLICATION_READ_BYTES: usize = 256 * 1024 + 2048;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ApplicationReadError {
    #[error("Application Security rejected an invalid read query")]
    InvalidQuery,
    #[error("Application Security returned invalid or stale evidence")]
    InvalidProjection,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationPageQuery {
    pub limit: u32,
    pub revision: Option<u64>,
    pub after: Option<SecurityReference>,
}

impl ApplicationPageQuery {
    /// # Errors
    /// Pagination is bounded and revision-bound; no path or UID selectors.
    pub fn validate(&self) -> Result<(), ApplicationReadError> {
        if !(1..=100).contains(&self.limit)
            || self
                .after
                .as_ref()
                .is_some_and(|value| value.namespace() != "installation" || self.revision.is_none())
        {
            return Err(ApplicationReadError::InvalidQuery);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedResourcePageQuery {
    pub limit: u32,
    pub revision: Option<u64>,
    pub after: Option<SecurityReference>,
}
impl ProtectedResourcePageQuery {
    /// # Errors
    /// Resource-only, bounded revision-bound pagination; no paths or UID selector.
    pub fn validate(&self) -> Result<(), ApplicationReadError> {
        if !(1..=100).contains(&self.limit)
            || self
                .after
                .as_ref()
                .is_some_and(|r| r.namespace() != "resource" || self.revision.is_none())
        {
            return Err(ApplicationReadError::InvalidQuery);
        }
        Ok(())
    }
}

fn resource(value: &ProtectedResource, revision: u64) -> Result<(), ApplicationReadError> {
    value
        .validate()
        .map_err(|_| ApplicationReadError::InvalidProjection)?;
    if value.owner_uid != rustix::process::getuid().as_raw()
        || !(1..=revision).contains(&value.policy_revision)
    {
        return Err(ApplicationReadError::InvalidProjection);
    }
    Ok(())
}

/// # Errors
/// Missing services remain unavailable. Coverage uses the authoritative source lease.
pub fn decode_protected_resource_page(
    raw: &str,
    query: &ProtectedResourcePageQuery,
    now: DateTime<Utc>,
) -> Result<ApplicationReadEnvelope<ProtectedResourcePage>, ApplicationReadError> {
    query.validate()?;
    let value: ApplicationReadEnvelope<ProtectedResourcePage> = decode(raw, now)?;
    if let Some(page) = &value.projection {
        if page.schema != APPLICATION_SECURITY_SCHEMA
            || page.policy_revision == 0
            || page.inventory_health != EnforcementHealth::Unknown
            || page.resources.len() > usize::try_from(query.limit).unwrap_or(0)
            || query.revision.is_some_and(|r| r != page.policy_revision)
        {
            return Err(ApplicationReadError::InvalidProjection);
        }
        let mut previous = query.after.as_ref();
        for entry in &page.resources {
            resource(entry, page.policy_revision)?;
            if previous.is_some_and(|r| r >= &entry.resource_ref) {
                return Err(ApplicationReadError::InvalidProjection);
            }
            previous = Some(&entry.resource_ref);
        }
        let next = if page.resources.len() == usize::try_from(query.limit).unwrap_or(0) {
            previous.cloned()
        } else {
            None
        };
        if page.next_cursor != next {
            return Err(ApplicationReadError::InvalidProjection);
        }
    }
    Ok(value)
}

/// # Errors
/// Foreign/mismatched objects and expired authoritative coverage leases refuse.
pub fn decode_protected_resource_lookup(
    raw: &str,
    reference: &SecurityReference,
    now: DateTime<Utc>,
) -> Result<ApplicationReadEnvelope<ProtectedResourceLookup>, ApplicationReadError> {
    if reference.namespace() != "resource" {
        return Err(ApplicationReadError::InvalidQuery);
    }
    let value: ApplicationReadEnvelope<ProtectedResourceLookup> = decode(raw, now)?;
    if let Some(projection) = &value.projection {
        if projection.schema != APPLICATION_SECURITY_SCHEMA || projection.policy_revision == 0 {
            return Err(ApplicationReadError::InvalidProjection);
        }
        if let Some(entry) = &projection.resource {
            resource(entry, projection.policy_revision)?;
            if &entry.resource_ref != reference {
                return Err(ApplicationReadError::InvalidProjection);
            }
        }
    }
    Ok(value)
}

fn decode<T: DeserializeOwned>(
    raw: &str,
    now: DateTime<Utc>,
) -> Result<ApplicationReadEnvelope<T>, ApplicationReadError> {
    if raw.len() > MAX_APPLICATION_READ_BYTES {
        return Err(ApplicationReadError::InvalidProjection);
    }
    let value: ApplicationReadEnvelope<T> =
        serde_json::from_str(raw).map_err(|_| ApplicationReadError::InvalidProjection)?;
    let available = value.source_state.state == ApplicationReadAvailability::Available;
    if value.schema != APPLICATION_SECURITY_SCHEMA
        || available != value.projection.is_some()
        || available == value.source_state.reason.is_some()
        || value.source_state.reason.as_ref().is_some_and(|reason| {
            ![
                "INVALID_REQUEST",
                "INVALID_PROJECTION",
                "INVALID_PROTECTION",
                "INVALID_IDENTITY",
                "INVALID_SCHEMA",
                "RESPONSE_LIMIT",
                "BROKER_UNAVAILABLE",
                "BROKER_AUTHORITY_UNAVAILABLE",
                "BROKER_CHANGED",
                "BROKER_DEADLINE",
            ]
            .contains(&reason.as_str())
        })
        || value.observed_at > now + Duration::seconds(1)
        || value.fresh_until < value.observed_at
        || value.fresh_until > value.observed_at + Duration::seconds(5)
        || (available && now >= value.fresh_until)
        || (!available && value.fresh_until != value.observed_at)
    {
        return Err(ApplicationReadError::InvalidProjection);
    }
    Ok(value)
}

fn protection(
    value: &ProtectionSnapshot,
    observed: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), ApplicationReadError> {
    value
        .validate()
        .map_err(|_| ApplicationReadError::InvalidProjection)?;
    let elapsed = u64::try_from((now - observed).num_milliseconds().max(0))
        .map_err(|_| ApplicationReadError::InvalidProjection)?;
    if value.effective_profile.is_some()
        && value
            .evidence_age_ms
            .is_none_or(|age| age.saturating_add(elapsed) > 30_000)
    {
        return Err(ApplicationReadError::InvalidProjection);
    }
    Ok(())
}

fn detail(
    value: &ApplicationReadDetails,
    uid: u32,
    observed: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), ApplicationReadError> {
    value
        .record
        .identity
        .validate()
        .map_err(|_| ApplicationReadError::InvalidProjection)?;
    if value.record.identity.owner_uid != uid || value.record.first_seen > value.record.last_seen {
        return Err(ApplicationReadError::InvalidProjection);
    }
    protection(&value.protection, observed, now)
}

/// # Errors
/// Missing providers stay unavailable; invalid evidence is never a safe empty list.
pub fn decode_application_coverage(
    raw: &str,
    now: DateTime<Utc>,
) -> Result<ApplicationReadEnvelope<ApplicationCoverage>, ApplicationReadError> {
    let value: ApplicationReadEnvelope<ApplicationCoverage> = decode(raw, now)?;
    if let Some(projection) = &value.projection {
        if projection.schema != APPLICATION_SECURITY_SCHEMA {
            return Err(ApplicationReadError::InvalidProjection);
        }
        protection(&projection.protection, value.observed_at, now)?;
    }
    Ok(value)
}

/// # Errors
/// Rejects wrong/foreign installations and invalid live protection projections.
pub fn decode_application_detail(
    raw: &str,
    reference: &SecurityReference,
    now: DateTime<Utc>,
) -> Result<ApplicationReadEnvelope<ApplicationLookup>, ApplicationReadError> {
    if reference.namespace() != "installation" {
        return Err(ApplicationReadError::InvalidQuery);
    }
    let value: ApplicationReadEnvelope<ApplicationLookup> = decode(raw, now)?;
    if let Some(projection) = &value.projection {
        if projection.schema != APPLICATION_SECURITY_SCHEMA {
            return Err(ApplicationReadError::InvalidProjection);
        }
        if let Some(application) = &projection.application {
            detail(
                application,
                rustix::process::getuid().as_raw(),
                value.observed_at,
                now,
            )?;
            if &application.record.identity.installation_ref != reference {
                return Err(ApplicationReadError::InvalidProjection);
            }
        }
    }
    Ok(value)
}

/// # Errors
/// Rejects stale, unordered, duplicate, foreign or over-budget pages/cursors.
pub fn decode_application_page(
    raw: &str,
    query: &ApplicationPageQuery,
    now: DateTime<Utc>,
) -> Result<ApplicationReadEnvelope<ApplicationInventoryPage>, ApplicationReadError> {
    query.validate()?;
    let value: ApplicationReadEnvelope<ApplicationInventoryPage> = decode(raw, now)?;
    if let Some(projection) = &value.projection {
        if projection.schema != APPLICATION_SECURITY_SCHEMA
            || projection.applications.len() > usize::try_from(query.limit).unwrap_or(0)
            || query
                .revision
                .is_some_and(|revision| revision != projection.inventory_revision)
        {
            return Err(ApplicationReadError::InvalidProjection);
        }
        let mut references = BTreeSet::new();
        let mut previous = query.after.as_ref();
        for application in &projection.applications {
            detail(
                application,
                rustix::process::getuid().as_raw(),
                value.observed_at,
                now,
            )?;
            let reference = &application.record.identity.installation_ref;
            if previous.is_some_and(|before| before >= reference) || !references.insert(reference) {
                return Err(ApplicationReadError::InvalidProjection);
            }
            previous = Some(reference);
        }
        let expected_cursor =
            if projection.applications.len() == usize::try_from(query.limit).unwrap_or(0) {
                previous.cloned()
            } else {
                None
            };
        if projection.next_cursor != expected_cursor {
            return Err(ApplicationReadError::InvalidProjection);
        }
    }
    Ok(value)
}
