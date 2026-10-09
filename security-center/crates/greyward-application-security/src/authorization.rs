//! Fresh, bounded Polkit checks for the broker's two fixed weakening purposes.
//! A ticket is private process memory, never a deserialized frontend credential.
use crate::{ExecutionHandle, PeerError, SystemPeerResolver, peer_bus::system_connection};
use dbus::arg::{PropMap, Variant};
use dbus::blocking::Connection;
use dbus::strings::BusName;
use greyward_security_domain::{ExecutionIdentity, SecurityReference};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use thiserror::Error;

const MAX_AUTH_WAIT: Duration = Duration::from_secs(30);
const TICKET_LEASE: Duration = Duration::from_secs(5);
type Decision = (bool, bool, HashMap<String, String>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationPurpose {
    /// Only the authenticated owner's per-user policy. No system policy grant.
    OwnerGrant,
    SystemPolicy,
}

impl AuthorizationPurpose {
    fn action(self) -> &'static str {
        match self {
            Self::OwnerGrant => "systems.mantis.greyward.application-security.grant-owner",
            Self::SystemPolicy => "systems.mantis.greyward.application-security.system-policy",
        }
    }
}

/// Construct from the broker's reviewed operation, not a generic UI action ID.
pub struct AuthorizationIntent {
    pub purpose: AuthorizationPurpose,
    pub operation_ref: SecurityReference,
    pub expected_revision: u64,
    pub deadline: Instant,
    pub interactive: bool,
}

impl AuthorizationIntent {
    fn remaining(&self, now: Instant) -> Result<Duration, AuthorizationError> {
        if self.operation_ref.namespace() != "operation" || self.expected_revision == 0 {
            return Err(AuthorizationError::InvalidIntent);
        }
        self.deadline
            .checked_duration_since(now)
            .filter(|remaining| !remaining.is_zero() && *remaining <= MAX_AUTH_WAIT)
            .ok_or(AuthorizationError::Deadline)
    }
}

#[derive(Debug, Error)]
pub enum AuthorizationError {
    #[error("Invalid reviewed authorization operation")]
    InvalidIntent,
    #[error("Fresh owner or administrator authentication is required")]
    AuthenticationRequired,
    #[error("The policy change is not authorized")]
    NotAuthorized,
    #[error("Authorization deadline expired")]
    Deadline,
    #[error("Authorization subject, operation or policy revision changed")]
    Changed,
    #[error("Retained authorization is not accepted for a weakening operation")]
    RetainedAuthorization,
    #[error(transparent)]
    Peer(#[from] PeerError),
    #[error(transparent)]
    Bus(#[from] dbus::Error),
}

pub struct AuthorizationTicket {
    sender: String,
    actor: ExecutionIdentity,
    purpose: AuthorizationPurpose,
    operation_ref: SecurityReference,
    revision: u64,
    expires: Instant,
}

impl AuthorizationTicket {
    fn validate_for(
        &self,
        intent: &AuthorizationIntent,
        sender: &str,
        actor: &ExecutionIdentity,
        now: Instant,
    ) -> Result<(), AuthorizationError> {
        if now >= self.expires || now >= intent.deadline {
            return Err(AuthorizationError::Deadline);
        }
        if self.sender != sender
            || self.actor != *actor
            || self.purpose != intent.purpose
            || self.operation_ref != intent.operation_ref
            || self.revision != intent.expected_revision
        {
            return Err(AuthorizationError::Changed);
        }
        Ok(())
    }

    /// Consume immediately before the root transaction, after policy/generation
    /// revalidation. The non-cloneable ticket cannot be replayed or transferred.
    /// `OwnerGrant` still requires the transaction's target UID to equal this actor.
    /// # Errors
    /// Expired/disconnected/replaced peers or changed operations fail closed.
    pub fn consume(
        self,
        intent: &AuthorizationIntent,
        sender: &BusName<'_>,
        actor: &ExecutionHandle,
        peers: &SystemPeerResolver,
    ) -> Result<(), AuthorizationError> {
        actor.revalidate().map_err(PeerError::from)?;
        self.validate_for(intent, sender, actor.identity(), Instant::now())?;
        let live = peers.resolve_until(sender, self.expires.min(intent.deadline))?;
        if live.identity() != actor.identity() {
            return Err(AuthorizationError::Changed);
        }
        self.validate_for(intent, sender, actor.identity(), Instant::now())
    }
}

pub struct SystemAuthorizer {
    connection: Connection,
    peers: SystemPeerResolver,
}

impl SystemAuthorizer {
    /// Consume this authority's non-transferable ticket immediately before the
    /// caller's revision-checked transaction. This does not establish kernel policy.
    /// # Errors
    /// Rechecks the live bus peer, process generation, operation and deadline.
    pub fn consume_ticket(
        &self,
        ticket: AuthorizationTicket,
        intent: &AuthorizationIntent,
        sender: &BusName<'_>,
        actor: &ExecutionHandle,
    ) -> Result<(), AuthorizationError> {
        ticket.consume(intent, sender, actor, &self.peers)
    }

    /// Fixed root-owned system bus; no session/environment-selected authority.
    /// # Errors
    /// Reports missing bus/credential capability without a permissive fallback.
    pub fn connect() -> Result<Self, AuthorizationError> {
        Ok(Self {
            connection: system_connection()?,
            peers: SystemPeerResolver::connect()?,
        })
    }

    fn cancel_check(&self, id: &str) {
        let proxy = self.connection.with_proxy(
            "org.freedesktop.PolicyKit1",
            "/org/freedesktop/PolicyKit1/Authority",
            Duration::from_millis(200),
        );
        let _: Result<(), dbus::Error> = proxy.method_call(
            "org.freedesktop.PolicyKit1.Authority",
            "CancelCheckAuthorization",
            (id,),
        );
    }

    /// This grants no resource access. The root broker must bind the intent to
    /// its preview, recheck the target UID/revision/generation and consume the
    /// ticket before an authoritative policy transaction and readback.
    /// # Errors
    /// Rejects unauthenticated, stale, retained or failed checks, never merely
    /// trusting same-UID/wheel membership or an application-supplied identity.
    pub fn authorize(
        &self,
        intent: &AuthorizationIntent,
        sender: &BusName<'_>,
        actor: &ExecutionHandle,
    ) -> Result<AuthorizationTicket, AuthorizationError> {
        intent.remaining(Instant::now())?;
        actor.revalidate().map_err(PeerError::from)?;
        let live = self.peers.resolve_until(sender, intent.deadline)?;
        if live.identity() != actor.identity() {
            return Err(AuthorizationError::Changed);
        }
        let mut subject = PropMap::new();
        subject.insert("name".into(), Variant(Box::new(sender.to_string())));
        let details: HashMap<String, String> = HashMap::from([
            (
                "greyward.operation".into(),
                intent.operation_ref.as_str().into(),
            ),
            (
                "greyward.policy_revision".into(),
                intent.expected_revision.to_string(),
            ),
        ]);
        let wait = intent.remaining(Instant::now())?;
        let proxy = self.connection.with_proxy(
            "org.freedesktop.PolicyKit1",
            "/org/freedesktop/PolicyKit1/Authority",
            wait,
        );
        let result: Result<(Decision,), dbus::Error> = proxy.method_call(
            "org.freedesktop.PolicyKit1.Authority",
            "CheckAuthorization",
            (
                ("system-bus-name", subject),
                intent.purpose.action(),
                details,
                u32::from(intent.interactive),
                intent.operation_ref.as_str(),
            ),
        );
        let ((authorized, challenge, details),) = match result {
            Ok(value) => value,
            Err(error) => {
                self.cancel_check(intent.operation_ref.as_str());
                return Err(error.into());
            }
        };
        if !authorized {
            return Err(if challenge {
                AuthorizationError::AuthenticationRequired
            } else {
                AuthorizationError::NotAuthorized
            });
        }
        if challenge
            || details
                .get("polkit.temporary_authorization_id")
                .is_some_and(|id| !id.is_empty())
            || details
                .get("polkit.retains_authorization_after_challenge")
                .is_some_and(|id| !id.is_empty())
        {
            return Err(AuthorizationError::RetainedAuthorization);
        }
        intent.remaining(Instant::now())?;
        actor.revalidate().map_err(PeerError::from)?;
        let live = self.peers.resolve_until(sender, intent.deadline)?;
        if live.identity() != actor.identity() {
            return Err(AuthorizationError::Changed);
        }
        let now = Instant::now();
        if now >= intent.deadline {
            return Err(AuthorizationError::Deadline);
        }
        Ok(AuthorizationTicket {
            sender: sender.to_string(),
            actor: actor.identity().clone(),
            purpose: intent.purpose,
            operation_ref: intent.operation_ref.clone(),
            revision: intent.expected_revision,
            expires: (now + TICKET_LEASE).min(intent.deadline),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(now: Instant) -> (AuthorizationTicket, AuthorizationIntent) {
        let operation_ref =
            SecurityReference::try_from(format!("operation_{}", "a".repeat(64))).unwrap();
        let actor = ExecutionIdentity {
            execution_ref: SecurityReference::try_from(format!("execution_{}", "b".repeat(64)))
                .unwrap(),
            installation_ref: None,
            owner_uid: 1000,
            boot_id: "12345678-1234-1234-1234-123456789abc".into(),
            pid: 42,
            start_ticks: 100,
            selinux_context: "user_u:user_r:user_t:s0".into(),
        };
        let ticket = AuthorizationTicket {
            sender: ":1.42".into(),
            actor,
            purpose: AuthorizationPurpose::OwnerGrant,
            operation_ref: operation_ref.clone(),
            revision: 5,
            expires: now + TICKET_LEASE,
        };
        let intent = AuthorizationIntent {
            purpose: AuthorizationPurpose::OwnerGrant,
            operation_ref,
            expected_revision: 5,
            deadline: now + MAX_AUTH_WAIT,
            interactive: false,
        };
        (ticket, intent)
    }

    #[test]
    fn an_authorization_is_bound_to_execution_sender_operation_and_revision() {
        let now = Instant::now();
        let (ticket, mut intent) = fixture(now);
        assert!(
            ticket
                .validate_for(&intent, ":1.42", &ticket.actor, now)
                .is_ok()
        );
        assert!(
            ticket
                .validate_for(&intent, ":1.43", &ticket.actor, now)
                .is_err()
        );
        let mut actor = ticket.actor.clone();
        actor.start_ticks += 1;
        assert!(ticket.validate_for(&intent, ":1.42", &actor, now).is_err());
        actor = ticket.actor.clone();
        actor.owner_uid += 1;
        assert!(ticket.validate_for(&intent, ":1.42", &actor, now).is_err());
        intent.expected_revision += 1;
        assert!(
            ticket
                .validate_for(&intent, ":1.42", &ticket.actor, now)
                .is_err()
        );
        intent.expected_revision = 5;
        intent.operation_ref =
            SecurityReference::try_from(format!("operation_{}", "c".repeat(64))).unwrap();
        assert!(
            ticket
                .validate_for(&intent, ":1.42", &ticket.actor, now)
                .is_err()
        );
    }

    #[test]
    fn an_owner_authorization_cannot_be_reused_for_system_policy() {
        let now = Instant::now();
        let (ticket, mut intent) = fixture(now);
        intent.purpose = AuthorizationPurpose::SystemPolicy;
        assert!(
            ticket
                .validate_for(&intent, ":1.42", &ticket.actor, now)
                .is_err()
        );
    }

    #[test]
    fn a_ticket_expires_even_if_the_peer_is_unchanged() {
        let now = Instant::now();
        let (ticket, intent) = fixture(now);
        assert!(matches!(
            ticket.validate_for(&intent, ":1.42", &ticket.actor, now + TICKET_LEASE),
            Err(AuthorizationError::Deadline)
        ));
    }

    #[test]
    fn authorization_waits_are_bounded_and_require_a_valid_operation() {
        let now = Instant::now();
        let (_, mut intent) = fixture(now);
        assert!(intent.remaining(now).is_ok());
        intent.deadline = now;
        assert!(intent.remaining(now).is_err());
        intent.deadline = now + MAX_AUTH_WAIT + Duration::from_secs(1);
        assert!(intent.remaining(now).is_err());
        intent.deadline = now + MAX_AUTH_WAIT;
        intent.operation_ref =
            SecurityReference::try_from(format!("grant_{}", "a".repeat(64))).unwrap();
        assert!(intent.remaining(now).is_err());
    }
}
