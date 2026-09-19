//! Stable, backend-independent domain contract for GREYWARD Security Center.
//!
//! This crate deliberately has no GTK, D-Bus, subprocess, or backend dependency.

mod context;
mod evaluate;
mod model;
mod snapshot;

pub use context::*;
pub use evaluate::{
    CheckDefinition, CheckObservation, EvidenceRequirement, PredicateResult, aggregate_domain,
    evaluate_applicability, evaluate_check, is_fresh,
};
pub use model::*;
pub use snapshot::{MAX_SNAPSHOT_BYTES, SnapshotError, parse_snapshot_v1};
