//! Typed read-only transport. Policy and launch mutations are not exposed until
//! their authorization, provider and readback implementations exist.
use crate::{
    ApplicationReads, ExecutionHandle, PeerError, PolicyStore, ReadError, SystemPeerResolver,
};
use dbus::arg::ArgType;
use dbus::channel::{MatchingReceiver, Sender};
use dbus::message::MatchRule;
use dbus::{Message, MessageType};
use greyward_security_domain::{
    APPLICATION_SECURITY_SCHEMA, EnforcementHealth, ProtectionProfile, ProtectionSnapshot,
    SecurityReference,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};
use thiserror::Error;

pub const BROKER_BUS: &str = "systems.mantis.greyward.ApplicationSecurity1";
pub const BROKER_PATH: &str = "/systems/mantis/greyward/ApplicationSecurity1";
pub const BROKER_INTERFACE: &str = BROKER_BUS;
const MAX_REPLY: usize = 256 * 1024;
const REQUEST_DEADLINE: Duration = Duration::from_secs(6);

const INTROSPECTION: &str = r#"<node>
<interface name="systems.mantis.greyward.ApplicationSecurity1">
<method name="ListApplications"><arg name="limit" type="u" direction="in"/><arg name="has_revision" type="b" direction="in"/><arg name="expected_revision" type="t" direction="in"/><arg name="after" type="s" direction="in"/><arg name="projection" type="s" direction="out"/></method>
<method name="GetApplication"><arg name="installation_ref" type="s" direction="in"/><arg name="projection" type="s" direction="out"/></method>
<method name="GetCoverage"><arg name="projection" type="s" direction="out"/></method>
<method name="ListProtectedResources"><arg name="limit" type="u" direction="in"/><arg name="has_revision" type="b" direction="in"/><arg name="expected_revision" type="t" direction="in"/><arg name="after" type="s" direction="in"/><arg name="projection" type="s" direction="out"/></method>
<method name="GetProtectedResource"><arg name="resource_ref" type="s" direction="in"/><arg name="projection" type="s" direction="out"/></method>
</interface>
<interface name="org.freedesktop.DBus.Introspectable"><method name="Introspect"><arg type="s" direction="out"/></method></interface>
</node>"#;

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("Root broker requires a root process")]
    NotRoot,
    #[error("Typed broker request is invalid")]
    InvalidRequest,
    #[error("Broker method is not implemented")]
    UnknownMethod,
    #[error("Broker request deadline expired")]
    Deadline,
    #[error("Broker read capacity reached")]
    Capacity,
    #[error("Broker projection exceeds its response budget")]
    ResponseLimit,
    #[error("Broker transport failed")]
    Transport,
    #[error(transparent)]
    Read(#[from] ReadError),
    #[error(transparent)]
    Peer(#[from] PeerError),
    #[error(transparent)]
    Bus(#[from] dbus::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadRequest {
    List {
        limit: usize,
        revision: Option<u64>,
        after: Option<SecurityReference>,
    },
    Get(SecurityReference),
    Resources {
        limit: usize,
        revision: Option<u64>,
        after: Option<SecurityReference>,
    },
    Resource(SecurityReference),
    Coverage,
    Introspect,
}

fn types(message: &Message, expected: &[ArgType]) -> bool {
    let mut iterator = message.iter_init();
    for kind in expected {
        if iterator.arg_type() != *kind {
            return false;
        }
        iterator.next();
    }
    iterator.arg_type() == ArgType::Invalid
}

fn reference(value: &str) -> Result<SecurityReference, BrokerError> {
    namespaced_reference(value, "installation")
}

fn namespaced_reference(value: &str, namespace: &str) -> Result<SecurityReference, BrokerError> {
    if value.len() != namespace.len() + 65 {
        return Err(BrokerError::InvalidRequest);
    }
    let reference =
        SecurityReference::try_from(value.to_owned()).map_err(|_| BrokerError::InvalidRequest)?;
    if reference.namespace() != namespace {
        return Err(BrokerError::InvalidRequest);
    }
    Ok(reference)
}

impl ReadRequest {
    /// No JSON argument, caller UID, filesystem path or execution command.
    /// # Errors
    /// Rejects wrong objects/interfaces, extra fields, unbounded references and
    /// unsupported operations before performing credential or database work.
    pub fn decode(message: &Message) -> Result<Self, BrokerError> {
        if message.msg_type() != MessageType::MethodCall
            || message.path().as_deref() != Some(BROKER_PATH)
        {
            return Err(BrokerError::UnknownMethod);
        }
        let interface = message.interface();
        let member = message.member();
        match (interface.as_deref(), member.as_deref()) {
            (Some("org.freedesktop.DBus.Introspectable"), Some("Introspect"))
                if types(message, &[]) =>
            {
                Ok(Self::Introspect)
            }
            (Some(BROKER_INTERFACE), Some("GetCoverage")) if types(message, &[]) => {
                Ok(Self::Coverage)
            }
            (Some(BROKER_INTERFACE), Some("GetApplication" | "GetProtectedResource"))
                if types(message, &[ArgType::String]) =>
            {
                let (value,): (&str,) = message
                    .read1()
                    .map(|value| (value,))
                    .map_err(|_| BrokerError::InvalidRequest)?;
                if member.as_deref() == Some("GetProtectedResource") {
                    Ok(Self::Resource(namespaced_reference(value, "resource")?))
                } else {
                    Ok(Self::Get(reference(value)?))
                }
            }
            (Some(BROKER_INTERFACE), Some("ListApplications" | "ListProtectedResources"))
                if types(
                    message,
                    &[
                        ArgType::UInt32,
                        ArgType::Boolean,
                        ArgType::UInt64,
                        ArgType::String,
                    ],
                ) =>
            {
                let (limit, has_revision, revision, after): (u32, bool, u64, &str) =
                    message.read4().map_err(|_| BrokerError::InvalidRequest)?;
                if !(1..=100).contains(&limit)
                    || (!has_revision && (revision != 0 || !after.is_empty()))
                {
                    return Err(BrokerError::InvalidRequest);
                }
                let resource = member.as_deref() == Some("ListProtectedResources");
                let limit = usize::try_from(limit).map_err(|_| BrokerError::InvalidRequest)?;
                let revision = has_revision.then_some(revision);
                let after = if after.is_empty() {
                    None
                } else {
                    Some(namespaced_reference(
                        after,
                        if resource { "resource" } else { "installation" },
                    )?)
                };
                if resource {
                    return Ok(Self::Resources {
                        limit,
                        revision,
                        after,
                    });
                }
                Ok(Self::List {
                    limit,
                    revision,
                    after,
                })
            }
            (
                Some(BROKER_INTERFACE),
                Some(
                    "ListApplications"
                    | "GetApplication"
                    | "GetCoverage"
                    | "ListProtectedResources"
                    | "GetProtectedResource",
                ),
            )
            | (Some("org.freedesktop.DBus.Introspectable"), Some("Introspect")) => {
                Err(BrokerError::InvalidRequest)
            }
            _ => Err(BrokerError::UnknownMethod),
        }
    }
}

type CoverageProjection = greyward_security_domain::ApplicationCoverage;
type DetailProjection = greyward_security_domain::ApplicationLookup;

fn encode(value: &impl Serialize) -> Result<String, BrokerError> {
    let result = serde_json::to_string(value)?;
    if result.len() > MAX_REPLY {
        return Err(BrokerError::ResponseLimit);
    }
    Ok(result)
}

/// The transport authenticates the actor before calling this projection layer.
/// # Errors
/// Identity, database, revision and deadline failures never become safe emptiness.
pub fn project_read(
    store: &PolicyStore,
    actor: &ExecutionHandle,
    request: ReadRequest,
    deadline: Instant,
) -> Result<String, BrokerError> {
    if Instant::now() >= deadline {
        return Err(BrokerError::Deadline);
    }
    actor.revalidate().map_err(ReadError::from)?;
    let reads = ApplicationReads::new(store);
    let result = match request {
        ReadRequest::List {
            limit,
            revision,
            after,
        } => encode(&reads.list(actor, after.as_ref(), revision, limit)?)?,
        ReadRequest::Get(reference) => encode(&DetailProjection {
            schema: APPLICATION_SECURITY_SCHEMA.into(),
            application: reads.get(actor, &reference)?,
        })?,
        ReadRequest::Resources {
            limit,
            revision,
            after,
        } => encode(&reads.resources(actor, after.as_ref(), revision, limit)?)?,
        ReadRequest::Resource(reference) => encode(&reads.resource(actor, &reference)?)?,
        ReadRequest::Coverage => encode(&CoverageProjection {
            schema: APPLICATION_SECURITY_SCHEMA.into(),
            inventory_health: EnforcementHealth::Unknown,
            protection: ProtectionSnapshot::from_evidence(
                ProtectionProfile::Protected,
                &store
                    .protection_prerequisites(actor)
                    .map_err(ReadError::from)?,
            ),
        })?,
        ReadRequest::Introspect => INTROSPECTION.to_owned(),
    };
    actor.revalidate().map_err(ReadError::from)?;
    if Instant::now() >= deadline {
        return Err(BrokerError::Deadline);
    }
    Ok(result)
}

// Bounded callback admission, not a claim that libdbus's receive allocation is
// bounded here. The service's cgroup provides the separate hard memory limit.
struct Admission {
    start: Instant,
    total: u8,
    senders: BTreeMap<String, u8>,
}

impl Admission {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            total: 0,
            senders: BTreeMap::new(),
        }
    }
    fn accept(&mut self, sender: &str, now: Instant) -> bool {
        if now.duration_since(self.start) >= Duration::from_secs(1) {
            self.start = now;
            self.total = 0;
            self.senders.clear();
        }
        if sender.len() > 255 || self.total >= 32 {
            return false;
        }
        let calls = self.senders.entry(sender.to_owned()).or_default();
        if *calls >= 8 {
            return false;
        }
        *calls += 1;
        self.total += 1;
        true
    }
}

fn error_reply(message: &Message, kind: &str, reason: &CStr) -> Message {
    message.error(
        &dbus::strings::ErrorName::new(kind).expect("Static D-Bus error name"),
        reason,
    )
}

fn public_error(message: &Message, error: &BrokerError) -> Message {
    match error {
        BrokerError::Capacity => error_reply(
            message,
            "org.freedesktop.DBus.Error.LimitsExceeded",
            c"Outstanding read budget exceeded",
        ),
        BrokerError::InvalidRequest => error_reply(
            message,
            "org.freedesktop.DBus.Error.InvalidArgs",
            c"Invalid bounded query",
        ),
        BrokerError::UnknownMethod => error_reply(
            message,
            "org.freedesktop.DBus.Error.UnknownMethod",
            c"Method unavailable",
        ),
        BrokerError::Read(ReadError::RevisionChanged) => error_reply(
            message,
            "systems.mantis.greyward.ApplicationSecurity1.RevisionChanged",
            c"Refresh inventory revision",
        ),
        _ => error_reply(
            message,
            "systems.mantis.greyward.ApplicationSecurity1.Unavailable",
            c"Authoritative projection unavailable",
        ),
    }
}

/// Root-only service loop; fixed system bus and read methods. One bounded worker
/// owns process/filesystem/database reads; no policy mutation worker is exposed.
/// # Errors
/// Refuses non-root processes, bus-name replacement and transport failures.
/// # Panics
/// Only if a compile-time D-Bus error name is invalid.
pub fn serve_reads(store: PolicyStore) -> Result<(), BrokerError> {
    if rustix::process::getuid().as_raw() != 0 || rustix::process::geteuid().as_raw() != 0 {
        return Err(BrokerError::NotRoot);
    }
    let connection = crate::peer_bus::system_connection()?;
    let resolver = SystemPeerResolver::connect()?;
    let worker = crate::read_worker::ReadWorker::new(move |sender, request, deadline| {
        let sender = dbus::strings::BusName::new(sender).map_err(|_| BrokerError::Transport)?;
        let actor = resolver.resolve_until(&sender, deadline)?;
        project_read(&store, &actor, request, deadline)
    })?;
    let result = connection.request_name(BROKER_BUS, false, false, true)?;
    if result != dbus::blocking::stdintf::org_freedesktop_dbus::RequestNameReply::PrimaryOwner {
        return Err(BrokerError::Transport);
    }
    let failed = Arc::new(AtomicBool::new(false));
    let send_failed = Arc::clone(&failed);
    let mut admission = Admission::new();
    connection.start_receive(
        MatchRule::new_method_call(),
        Box::new(move |message, transport| {
            let deadline = Instant::now() + REQUEST_DEADLINE;
            let response = match ReadRequest::decode(&message) {
                Err(error) => public_error(&message, &error),
                Ok(request) => {
                    if let Some(sender) = message.sender().filter(|sender| sender.starts_with(':'))
                    {
                        if admission.accept(&sender, Instant::now()) {
                            let result = worker.call(&sender, request, deadline);
                            match result {
                                Ok(projection) => message.return_with_args((projection,)),
                                Err(error) => public_error(&message, &error),
                            }
                        } else {
                            error_reply(
                                &message,
                                "org.freedesktop.DBus.Error.LimitsExceeded",
                                c"Bounded query budget exceeded",
                            )
                        }
                    } else {
                        public_error(&message, &BrokerError::Transport)
                    }
                }
            };
            if transport.send(response).is_err() {
                send_failed.store(true, Ordering::Relaxed);
            }
            true
        }),
    );
    while !failed.load(Ordering::Relaxed) {
        connection.process(Duration::from_millis(100))?;
    }
    Err(BrokerError::Transport)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn connection_churn_cannot_remove_the_global_budget() {
        let mut admission = Admission::new();
        let now = admission.start;
        for index in 0..32 {
            assert!(admission.accept(&format!(":1.{index}"), now));
        }
        assert!(!admission.accept(":1.999", now));
        assert_eq!(admission.senders.len(), 32);
        assert!(admission.accept(":1.999", now + Duration::from_secs(1)));
        assert_eq!(admission.senders.len(), 1);
        for _ in 1..8 {
            assert!(admission.accept(":1.999", now + Duration::from_secs(1)));
        }
        assert!(!admission.accept(":1.999", now + Duration::from_secs(1)));
    }
}
