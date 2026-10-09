//! Functional development transport. Fixed isolated account/provider/storage;
//! never activated by the installed production read service. One bounded worker
//! owns mutation payloads, while `GetOperation` remains responsive during Polkit.
use crate::{
    BROKER_INTERFACE, BROKER_PATH, BrokerError, DevelopmentWorkflow, OperationTable, ReadRequest,
    SystemPeerResolver, WorkflowError,
};
use dbus::arg::ArgType;
use dbus::channel::{MatchingReceiver, Sender};
use dbus::message::MatchRule;
use dbus::{Message, MessageType};
use greyward_security_domain::{
    ExecutionIdentity, OperationOutcome, ProtectedCategory, SecurityReference,
};
use std::collections::BTreeMap;
use std::fs::File;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

pub const DEVELOPMENT_BROKER_BUS: &str = "systems.mantis.greyward.ApplicationSecurityDevelopment1";
const WAIT: Duration = Duration::from_secs(6);
const QUEUE: usize = 8;
const WORKFLOW_METHODS: &str = r#"
<method name="StartDesktop"><arg type="b" direction="out"/></method>
<method name="RequestAdministration"><arg type="as" direction="in"/><arg type="b" direction="out"/></method>
<method name="GetAdministrationState"><arg type="s" direction="out"/></method>
<method name="GetDeviceProtection"><arg type="s" direction="out"/></method>
<method name="RequestSessionLock"><arg type="b" direction="out"/></method>
<method name="GetSessionLock"><arg type="b" direction="out"/></method>
<method name="ReadSecurityEvents"><arg type="t" direction="in"/><arg type="u" direction="in"/><arg type="s" direction="out"/></method>
<method name="ListAccessGrants"><arg type="s" direction="out"/></method>
<method name="PreviewResourceRegistration"><arg type="h" direction="in"/><arg type="s" direction="in"/><arg type="s" direction="in"/><arg type="t" direction="in"/><arg type="s" direction="out"/></method>
<method name="PreviewPolicyChange"><arg type="s" direction="in"/><arg type="as" direction="in"/><arg type="t" direction="in"/><arg type="s" direction="out"/></method>
<method name="PreviewGrantRevocation"><arg type="s" direction="in"/><arg type="s" direction="in"/><arg type="t" direction="in"/><arg type="s" direction="out"/></method>
<method name="ApplyPolicyChange"><arg type="s" direction="in"/><arg type="b" direction="in"/><arg type="s" direction="out"/></method>
<method name="GetOperation"><arg type="s" direction="in"/><arg type="s" direction="out"/></method>
<method name="CancelOperation"><arg type="s" direction="in"/><arg type="s" direction="out"/></method>
<method name="PrepareLaunch"><arg type="s" direction="in"/><arg type="s" direction="in"/><arg type="as" direction="in"/><arg type="s" direction="out"/></method>
<method name="PrepareIsolatedLaunch"><arg type="h" direction="in"/><arg type="as" direction="in"/><arg type="s" direction="out"/></method>
<method name="PrepareGraphicalLaunch"><arg type="h" direction="in"/><arg type="as" direction="in"/><arg type="s" direction="out"/></method>
<method name="PrepareSelectedDocumentLaunch"><arg type="h" direction="in"/><arg type="s" direction="in"/><arg type="as" direction="in"/><arg type="b" direction="in"/><arg type="s" direction="out"/></method>
<method name="StartPreparedLaunch"><arg type="s" direction="in"/><arg type="h" direction="out"/><arg type="h" direction="out"/><arg type="h" direction="out"/></method>
<method name="GetLaunch"><arg type="s" direction="in"/><arg type="b" direction="out"/><arg type="i" direction="out"/></method>
"#;

pub enum WorkflowRequest {
    Desktop,
    Administration(Vec<String>),
    AdministrationState,
    Devices,
    Lock,
    LockStatus,
    Events {
        cursor: u64,
        limit: u32,
    },
    Read(ReadRequest),
    Grants,
    Registration {
        directory: File,
        category: ProtectedCategory,
        label: String,
        revision: u64,
    },
    Grant {
        path: String,
        resources: Vec<SecurityReference>,
        revision: u64,
    },
    Revoke {
        grant: SecurityReference,
        path: String,
        revision: u64,
    },
    Apply {
        operation: SecurityReference,
        interactive: bool,
    },
    Prepare {
        grant: SecurityReference,
        path: String,
        arguments: Vec<String>,
    },
    PrepareIsolated {
        candidate: File,
        arguments: Vec<String>,
        graphical: bool,
    },
    PrepareDocument {
        selected: File,
        handler: String,
        arguments: Vec<String>,
        graphical: bool,
    },
    Start(SecurityReference),
    Operation(SecurityReference),
    Cancel(SecurityReference),
    Launch(SecurityReference),
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
fn reference(value: &str, namespace: &str) -> Result<SecurityReference, BrokerError> {
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
fn path(value: &str) -> Result<(), BrokerError> {
    greyward_security_domain::InstalledExecutablePath::try_from(value)
        .map_err(|_| BrokerError::InvalidRequest)?;
    Ok(())
}

impl WorkflowRequest {
    /// # Errors
    /// Exact typed signatures, fixed object/interface and bounded arguments.
    /// Unknown operations cannot become generic command or policy requests.
    #[allow(clippy::too_many_lines)] // The fixed protocol is audited together.
    pub fn decode(message: &Message) -> Result<Self, BrokerError> {
        if let Ok(read) = ReadRequest::decode(message) {
            return Ok(Self::Read(read));
        }
        if message.msg_type() != MessageType::MethodCall
            || message.path().as_deref() != Some(BROKER_PATH)
            || message.interface().as_deref() != Some(BROKER_INTERFACE)
        {
            return Err(BrokerError::UnknownMethod);
        }
        if message.member().as_deref() == Some("StartDesktop") && types(message, &[]) {
            return Ok(Self::Desktop);
        }
        if message.member().as_deref() == Some("RequestAdministration")
            && types(message, &[ArgType::Array])
        {
            let (arguments,): (Vec<String>,) = message
                .read1()
                .map(|a| (a,))
                .map_err(|_| BrokerError::InvalidRequest)?;
            if arguments.is_empty()
                || arguments.len() > 128
                || arguments.iter().map(String::len).sum::<usize>() > 16384
                || arguments.iter().any(|a| a.chars().any(char::is_control))
            {
                return Err(BrokerError::InvalidRequest);
            }
            return Ok(Self::Administration(arguments));
        }
        if message.member().as_deref() == Some("GetDeviceProtection") && types(message, &[]) {
            return Ok(Self::Devices);
        }
        if message.member().as_deref() == Some("GetAdministrationState") && types(message, &[]) {
            return Ok(Self::AdministrationState);
        }
        if message.member().as_deref() == Some("RequestSessionLock") && types(message, &[]) {
            return Ok(Self::Lock);
        }
        if message.member().as_deref() == Some("GetSessionLock") && types(message, &[]) {
            return Ok(Self::LockStatus);
        }
        let member = message.member();
        match member.as_deref() {
            Some("ReadSecurityEvents") if types(message, &[ArgType::UInt64, ArgType::UInt32]) => {
                let (cursor, limit): (u64, u32) =
                    message.read2().map_err(|_| BrokerError::InvalidRequest)?;
                if !(1..=100).contains(&limit) {
                    return Err(BrokerError::InvalidRequest);
                }
                Ok(Self::Events { cursor, limit })
            }
            Some("ListAccessGrants") if types(message, &[]) => Ok(Self::Grants),
            Some("PreviewResourceRegistration")
                if types(
                    message,
                    &[
                        ArgType::UnixFd,
                        ArgType::String,
                        ArgType::String,
                        ArgType::UInt64,
                    ],
                ) =>
            {
                let (directory, category, label, revision): (File, String, String, u64) =
                    message.read4().map_err(|_| BrokerError::InvalidRequest)?;
                let category = match category.as_str() {
                    "CREDENTIALS" => ProtectedCategory::Credentials,
                    "CLOUD" => ProtectedCategory::Cloud,
                    "DEVELOPMENT" => ProtectedCategory::Development,
                    "BROWSER_SESSION" => ProtectedCategory::BrowserSession,
                    "CUSTOM" => ProtectedCategory::Custom,
                    _ => return Err(BrokerError::InvalidRequest),
                };
                if label.is_empty()
                    || label.len() > 128
                    || label.chars().any(char::is_control)
                    || revision == 0
                {
                    return Err(BrokerError::InvalidRequest);
                }
                Ok(Self::Registration {
                    directory,
                    category,
                    label,
                    revision,
                })
            }
            Some("PreviewPolicyChange")
                if types(message, &[ArgType::String, ArgType::Array, ArgType::UInt64]) =>
            {
                let (path_value, values, revision): (String, Vec<String>, u64) =
                    message.read3().map_err(|_| BrokerError::InvalidRequest)?;
                path(&path_value)?;
                if values.is_empty() || values.len() > 64 || revision == 0 {
                    return Err(BrokerError::InvalidRequest);
                }
                let resources = values
                    .iter()
                    .map(|v| reference(v, "resource"))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Self::Grant {
                    path: path_value,
                    resources,
                    revision,
                })
            }
            Some("PreviewGrantRevocation")
                if types(
                    message,
                    &[ArgType::String, ArgType::String, ArgType::UInt64],
                ) =>
            {
                let (grant, path_value, revision): (String, String, u64) =
                    message.read3().map_err(|_| BrokerError::InvalidRequest)?;
                if !path_value.is_empty() {
                    path(&path_value)?;
                }
                if revision == 0 {
                    return Err(BrokerError::InvalidRequest);
                }
                Ok(Self::Revoke {
                    grant: reference(&grant, "grant")?,
                    path: path_value,
                    revision,
                })
            }
            Some("ApplyPolicyChange") if types(message, &[ArgType::String, ArgType::Boolean]) => {
                let (operation, interactive): (String, bool) =
                    message.read2().map_err(|_| BrokerError::InvalidRequest)?;
                Ok(Self::Apply {
                    operation: reference(&operation, "operation")?,
                    interactive,
                })
            }
            Some("PrepareLaunch")
                if types(message, &[ArgType::String, ArgType::String, ArgType::Array]) =>
            {
                let (grant, path_value, arguments): (String, String, Vec<String>) =
                    message.read3().map_err(|_| BrokerError::InvalidRequest)?;
                path(&path_value)?;
                if arguments.len() > 32
                    || arguments.iter().any(|v| v.len() > 4096 || v.contains('\0'))
                    || arguments.iter().map(String::len).sum::<usize>() > 8192
                {
                    return Err(BrokerError::InvalidRequest);
                }
                Ok(Self::Prepare {
                    grant: reference(&grant, "grant")?,
                    path: path_value,
                    arguments,
                })
            }
            Some("PrepareSelectedDocumentLaunch")
                if types(
                    message,
                    &[
                        ArgType::UnixFd,
                        ArgType::String,
                        ArgType::Array,
                        ArgType::Boolean,
                    ],
                ) =>
            {
                let (selected, handler, arguments, graphical): (File, String, Vec<String>, bool) =
                    message.read4().map_err(|_| BrokerError::InvalidRequest)?;
                path(&handler)?;
                if arguments.len() > 32
                    || arguments.iter().any(|v| v.len() > 4096 || v.contains('\0'))
                    || arguments.iter().map(String::len).sum::<usize>() > 8192
                {
                    return Err(BrokerError::InvalidRequest);
                }
                Ok(Self::PrepareDocument {
                    selected,
                    handler,
                    arguments,
                    graphical,
                })
            }
            Some("PrepareIsolatedLaunch" | "PrepareGraphicalLaunch")
                if types(message, &[ArgType::UnixFd, ArgType::Array]) =>
            {
                let (candidate, arguments): (File, Vec<String>) =
                    message.read2().map_err(|_| BrokerError::InvalidRequest)?;
                if arguments.len() > 32
                    || arguments.iter().any(|v| v.len() > 4096 || v.contains('\0'))
                    || arguments.iter().map(String::len).sum::<usize>() > 8192
                {
                    return Err(BrokerError::InvalidRequest);
                }
                Ok(Self::PrepareIsolated {
                    candidate,
                    arguments,
                    graphical: member.as_deref() == Some("PrepareGraphicalLaunch"),
                })
            }
            Some("StartPreparedLaunch" | "GetLaunch" | "GetOperation" | "CancelOperation")
                if types(message, &[ArgType::String]) =>
            {
                let value: String = message.read1().map_err(|_| BrokerError::InvalidRequest)?;
                let launch = matches!(member.as_deref(), Some("StartPreparedLaunch" | "GetLaunch"));
                let reference = reference(&value, if launch { "launch" } else { "operation" })?;
                match member.as_deref() {
                    Some("StartPreparedLaunch") => Ok(Self::Start(reference)),
                    Some("GetLaunch") => Ok(Self::Launch(reference)),
                    Some("CancelOperation") => Ok(Self::Cancel(reference)),
                    _ => Ok(Self::Operation(reference)),
                }
            }
            Some(
                "PreviewResourceRegistration"
                | "PreviewPolicyChange"
                | "PreviewGrantRevocation"
                | "ApplyPolicyChange"
                | "PrepareLaunch"
                | "PrepareIsolatedLaunch"
                | "StartPreparedLaunch"
                | "GetLaunch"
                | "GetOperation"
                | "CancelOperation",
            ) => Err(BrokerError::InvalidRequest),
            _ => Err(BrokerError::UnknownMethod),
        }
    }
}

struct Job {
    sender: String,
    request: WorkflowRequest,
    message: Option<Message>,
    deadline: Instant,
}
struct LaunchRecord {
    actor: ExecutionIdentity,
    exit: Option<i32>,
    deadline: Instant,
}
type LaunchTable = Arc<Mutex<BTreeMap<SecurityReference, LaunchRecord>>>;

fn unavailable(message: &Message) -> Message {
    message.error(
        &dbus::strings::ErrorName::new("systems.mantis.greyward.ApplicationSecurity1.Unavailable")
            .expect("Static name"),
        c"Typed development provider unavailable; no fallback",
    )
}
fn queued_message(message: &Message) -> Result<Message, BrokerError> {
    // libdbus message_copy deliberately clears the serial. Preserve only the
    // bus-stamped incoming call's nonzero serial for the eventual worker reply.
    let serial = message.get_serial().ok_or(BrokerError::InvalidRequest)?;
    let mut copy = message.duplicate().map_err(|_| BrokerError::Transport)?;
    copy.set_serial(serial);
    Ok(copy)
}
fn encoded(value: &impl serde::Serialize) -> Result<String, WorkflowError> {
    let encoded = serde_json::to_string(value).map_err(|_| WorkflowError::Unavailable)?;
    if encoded.len() > 256 * 1024 {
        return Err(WorkflowError::Unavailable);
    }
    Ok(encoded)
}

#[allow(clippy::too_many_lines)] // Fixed operation dispatch keeps every side effect in one worker.
fn worker(
    jobs: &mpsc::Receiver<Job>,
    replies: &mpsc::SyncSender<Message>,
    mut workflow: Option<DevelopmentWorkflow>,
    operations: &Arc<Mutex<OperationTable>>,
    resolver: &SystemPeerResolver,
    launches: &LaunchTable,
) {
    let mut owners = BTreeMap::new();
    while let Ok(job) = jobs.recv() {
        let result = (|| -> Result<Option<Message>, WorkflowError> {
            if Instant::now() >= job.deadline {
                return Err(WorkflowError::Deadline);
            }
            let sender =
                dbus::strings::BusName::new(&job.sender).map_err(|_| WorkflowError::Unavailable)?;
            let actor = resolver
                .resolve_until(&sender, Instant::now() + WAIT)
                .map_err(|_| WorkflowError::Unavailable)?;
            if matches!(job.request, WorkflowRequest::Desktop) {
                if workflow.is_some() {
                    return Err(WorkflowError::Unavailable);
                }
                crate::desktop::start(&actor)?;
                let message = job.message.as_ref().ok_or(WorkflowError::Unavailable)?;
                return Ok(Some(message.return_with_args((true,))));
            }
            if let WorkflowRequest::Administration(arguments) = &job.request {
                if workflow.is_some() {
                    return Err(WorkflowError::Unavailable);
                }
                crate::administration::request(&actor, arguments)?;
                return Ok(Some(
                    job.message
                        .as_ref()
                        .ok_or(WorkflowError::Unavailable)?
                        .return_with_args((true,)),
                ));
            }
            if matches!(job.request, WorkflowRequest::Devices) {
                if workflow.is_some() {
                    return Err(WorkflowError::Unavailable);
                }
                return Ok(Some(
                    job.message
                        .as_ref()
                        .ok_or(WorkflowError::Unavailable)?
                        .return_with_args((crate::administration::devices()?,)),
                ));
            }
            if matches!(job.request, WorkflowRequest::AdministrationState) {
                if workflow.is_some() {
                    return Err(WorkflowError::Unavailable);
                }
                return Ok(Some(
                    job.message
                        .as_ref()
                        .ok_or(WorkflowError::Unavailable)?
                        .return_with_args((crate::administration::state(
                            actor.identity().owner_uid,
                        )?,)),
                ));
            }
            if matches!(
                job.request,
                WorkflowRequest::Lock | WorkflowRequest::LockStatus
            ) {
                if workflow.is_some() {
                    return Err(WorkflowError::Unavailable);
                }
                let result = if matches!(job.request, WorkflowRequest::Lock) {
                    crate::desktop::lock(&actor)?;
                    true
                } else {
                    crate::desktop::locked(actor.identity().owner_uid)
                };
                let message = job.message.as_ref().ok_or(WorkflowError::Unavailable)?;
                return Ok(Some(message.return_with_args((result,))));
            }
            if workflow.is_none() {
                if let WorkflowRequest::Read(request) = &job.request {
                    let store = crate::PolicyStore::open_system()?;
                    if store
                        .enrollment(actor.identity().owner_uid)?
                        .is_none_or(|r| !r.permits_provider())
                    {
                        let projection =
                            crate::project_read(&store, &actor, request.clone(), job.deadline)
                                .map_err(|_| WorkflowError::Unavailable)?;
                        let projection = if matches!(request, ReadRequest::Introspect) {
                            projection.replacen(
                                "</interface>",
                                &format!("{WORKFLOW_METHODS}</interface>"),
                                1,
                            )
                        } else {
                            projection
                        };
                        let message = job.message.as_ref().ok_or(WorkflowError::Unavailable)?;
                        return Ok(Some(message.return_with_args((projection,))));
                    }
                }
            }
            let workflow = if let Some(development) = workflow.as_mut() {
                development
            } else {
                let uid = actor.identity().owner_uid;
                if !owners.contains_key(&uid) {
                    if owners.len() >= 32 {
                        return Err(WorkflowError::Capacity);
                    }
                    let store = crate::PolicyStore::open_system()?;
                    let enrolled = store.enrollment(uid)?.is_some_and(|r| r.permits_provider());
                    owners.insert(
                        uid,
                        if enrolled {
                            DevelopmentWorkflow::open_production(uid, Arc::clone(operations))?
                        } else {
                            DevelopmentWorkflow::open_isolation(uid, Arc::clone(operations))?
                        },
                    );
                }
                owners.get_mut(&uid).ok_or(WorkflowError::Unavailable)?
            };
            workflow.expire();
            if let WorkflowRequest::Apply {
                operation,
                interactive,
            } = job.request
            {
                workflow.apply(&actor, &sender, &operation, interactive)?;
                return Ok(None);
            }
            let message = job.message.as_ref().ok_or(WorkflowError::Unavailable)?;
            let response = match job.request {
                WorkflowRequest::Events { cursor, limit } => {
                    workflow.security_events(&actor, cursor, limit)?
                }
                WorkflowRequest::Grants => workflow.grants(&actor)?,
                WorkflowRequest::Read(request) => {
                    let introspect = matches!(request, ReadRequest::Introspect);
                    let projection = workflow
                        .read(&actor, request, job.deadline)
                        .map_err(|_| WorkflowError::Unavailable)?;
                    if introspect {
                        projection.replacen(
                            "</interface>",
                            &format!("{WORKFLOW_METHODS}</interface>"),
                            1,
                        )
                    } else {
                        projection
                    }
                }
                WorkflowRequest::Registration {
                    directory,
                    category,
                    label,
                    revision,
                } => encoded(&workflow.preview_registration(
                    &actor,
                    directory.into(),
                    category,
                    label,
                    revision,
                )?)?,
                WorkflowRequest::Grant {
                    path,
                    resources,
                    revision,
                } => encoded(&workflow.preview_read_grant(&actor, &path, resources, revision)?)?,
                WorkflowRequest::Revoke {
                    grant,
                    path,
                    revision,
                } => encoded(&workflow.preview_revoke(&actor, &grant, &path, revision)?)?,
                WorkflowRequest::Prepare {
                    grant,
                    path,
                    arguments,
                } => workflow
                    .prepare_launch(&actor, &grant, &path, arguments)?
                    .as_str()
                    .to_owned(),
                WorkflowRequest::PrepareIsolated {
                    candidate,
                    arguments,
                    graphical,
                } => if graphical {
                    workflow.prepare_graphical(&actor, candidate.into(), arguments)?
                } else {
                    workflow.prepare_isolated(&actor, candidate.into(), arguments)?
                }
                .as_str()
                .to_owned(),
                WorkflowRequest::PrepareDocument {
                    selected,
                    handler,
                    arguments,
                    graphical,
                } => workflow
                    .prepare_document(&actor, selected.into(), &handler, arguments, graphical)?
                    .as_str()
                    .to_owned(),
                WorkflowRequest::Start(reference) => {
                    let mut running = workflow.start_launch(&actor, &reference)?;
                    let (input, output, error) = running.streams()?;
                    {
                        let mut records =
                            launches.lock().map_err(|_| WorkflowError::Unavailable)?;
                        records.retain(|_, r| r.deadline > Instant::now());
                        if records.len() >= 32 || records.contains_key(&reference) {
                            return Err(WorkflowError::Capacity);
                        }
                        records.insert(
                            reference.clone(),
                            LaunchRecord {
                                actor: actor.identity().clone(),
                                exit: None,
                                deadline: Instant::now() + Duration::from_secs(3660),
                            },
                        );
                    }
                    let records = Arc::clone(launches);
                    std::thread::Builder::new()
                        .name("reviewed-launch-wait".into())
                        .spawn(move || {
                            let exit = running.wait().ok().and_then(|s| s.code()).unwrap_or(125);
                            if let Ok(mut records) = records.lock() {
                                if let Some(record) = records.get_mut(&reference) {
                                    record.exit = Some(exit);
                                }
                            }
                        })
                        .map_err(|_| WorkflowError::Unavailable)?;
                    return Ok(Some(message.return_with_args((input, output, error))));
                }
                // Only the workflow owner handles protected seat/admin/device
                // operations. Unsupported requests never enter this provider.
                _ => return Err(WorkflowError::Unavailable),
            };
            if Instant::now() >= job.deadline {
                return Err(WorkflowError::Deadline);
            }
            Ok(Some(message.return_with_args((response,))))
        })();
        let reply = match result {
            Ok(reply) => reply,
            Err(error) => {
                // Fixed provider diagnostics contain error kinds only; no request
                // arguments, descriptors, resource paths or application output.
                eprintln!("Development workflow failed: {error}");
                job.message.as_ref().map(unavailable)
            }
        };
        if let Some(reply) = reply {
            if replies.send(reply).is_err() {
                return;
            }
        }
    }
}

/// # Errors
/// Fixed root-owned bus/provider only. Preview calls queue bounded work; apply
/// acknowledges submission, and `GetOperation` supplies the verified outcome.
/// # Panics
/// Only if a fixed compile-time D-Bus error name is invalid.
#[allow(clippy::too_many_lines)] // Admission, owner checks and queue handoff form one boundary.
pub fn serve_development() -> Result<(), BrokerError> {
    serve_workflows(false)
}

/// Production mutations require an enrolled owner and every existing typed authorization gate.
/// Enrollment metadata alone never changes UNKNOWN coverage into PROTECTED.
/// # Errors
/// Unavailable configuration, transport or worker refuses without launching.
pub fn serve_enrolled() -> Result<(), BrokerError> {
    serve_workflows(true)
}

#[allow(clippy::too_many_lines)]
fn serve_workflows(production: bool) -> Result<(), BrokerError> {
    if rustix::process::getuid().as_raw() != 0 || rustix::process::geteuid().as_raw() != 0 {
        return Err(BrokerError::NotRoot);
    }
    let operations = Arc::new(Mutex::new(OperationTable::default()));
    let launches = Arc::new(Mutex::new(BTreeMap::new()));
    let workflow = if production {
        None
    } else {
        Some(
            DevelopmentWorkflow::open(Arc::clone(&operations))
                .map_err(|_| BrokerError::Transport)?,
        )
    };
    let worker_operations = Arc::clone(&operations);
    let resolver = SystemPeerResolver::connect()?;
    let worker_resolver = SystemPeerResolver::connect()?;
    let (jobs, receiver) = mpsc::sync_channel(QUEUE);
    let (replies, response) = mpsc::sync_channel(QUEUE);
    let worker_launches = Arc::clone(&launches);
    std::thread::Builder::new()
        .name("application-policy-worker".into())
        .spawn(move || {
            worker(
                &receiver,
                &replies,
                workflow,
                &worker_operations,
                &worker_resolver,
                &worker_launches,
            );
        })
        .map_err(|_| BrokerError::Transport)?;
    let connection = crate::peer_bus::system_connection()?;
    if connection.request_name(
        if production {
            crate::BROKER_BUS
        } else {
            DEVELOPMENT_BROKER_BUS
        },
        false,
        false,
        true,
    )? != dbus::blocking::stdintf::org_freedesktop_dbus::RequestNameReply::PrimaryOwner
    {
        return Err(BrokerError::Transport);
    }
    let mut window = Instant::now();
    let mut count = 0_u8;
    connection.start_receive(
        MatchRule::new_method_call(),
        Box::new(move |message, transport| {
            let now = Instant::now();
            if now.duration_since(window) >= Duration::from_secs(1) {
                window = now;
                count = 0;
            }
            let result = (|| -> Result<Option<Message>, BrokerError> {
                if count >= 32 {
                    return Err(BrokerError::Capacity);
                }
                count += 1;
                let request = WorkflowRequest::decode(&message)?;
                let sender = message
                    .sender()
                    .filter(|s| s.starts_with(':'))
                    .ok_or(BrokerError::Transport)?;
                if matches!(
                    request,
                    WorkflowRequest::Operation(_)
                        | WorkflowRequest::Cancel(_)
                        | WorkflowRequest::Apply { .. }
                        | WorkflowRequest::Launch(_)
                ) {
                    let actor = resolver.resolve_until(&sender, now + WAIT)?;
                    if !production && actor.identity().owner_uid != 1002 {
                        return Err(BrokerError::Transport);
                    }
                    if let WorkflowRequest::Launch(reference) = &request {
                        let records = launches.lock().map_err(|_| BrokerError::Transport)?;
                        let record = records
                            .get(reference)
                            .filter(|r| r.actor == *actor.identity() && r.deadline > Instant::now())
                            .ok_or(BrokerError::Transport)?;
                        return Ok(Some(message.return_with_args((
                            record.exit.is_some(),
                            record.exit.unwrap_or(0),
                        ))));
                    }
                    let reference = match &request {
                        WorkflowRequest::Operation(r) | WorkflowRequest::Cancel(r) => r,
                        WorkflowRequest::Apply { operation, .. } => operation,
                        _ => return Err(BrokerError::InvalidRequest),
                    };
                    let mut table = operations.lock().map_err(|_| BrokerError::Transport)?;
                    let current = table
                        .get(reference, actor.identity())
                        .map_err(|_| BrokerError::Transport)?;
                    if matches!(request, WorkflowRequest::Cancel(_)) {
                        // Running authentication/commit cannot truthfully be called
                        // cancelled. Only unstarted reviews support cancellation.
                        if current.outcome != OperationOutcome::Pending {
                            return Err(BrokerError::InvalidRequest);
                        }
                        table
                            .cancel(reference, actor.identity())
                            .map_err(|_| BrokerError::Transport)?;
                        let result = table
                            .get(reference, actor.identity())
                            .map_err(|_| BrokerError::Transport)?;
                        return Ok(Some(
                            message.return_with_args((serde_json::to_string(&result)?,)),
                        ));
                    }
                    if matches!(request, WorkflowRequest::Operation(_)) {
                        return Ok(Some(
                            message.return_with_args((serde_json::to_string(&current)?,)),
                        ));
                    }
                    if current.outcome != OperationOutcome::Pending {
                        return Err(BrokerError::InvalidRequest);
                    }
                    jobs.try_send(Job {
                        sender: sender.to_string(),
                        request,
                        message: None,
                        deadline: now + Duration::from_secs(100),
                    })
                    .map_err(|_| BrokerError::Capacity)?;
                    return Ok(Some(
                        message.return_with_args((serde_json::to_string(&current)?,)),
                    ));
                }
                jobs.try_send(Job {
                    sender: sender.to_string(),
                    request,
                    message: Some(queued_message(&message)?),
                    deadline: now + WAIT,
                })
                .map_err(|_| BrokerError::Capacity)?;
                Ok(None)
            })();
            if let Some(reply) = result.unwrap_or_else(|_| Some(unavailable(&message))) {
                let _ = transport.send(reply);
            }
            true
        }),
    );
    loop {
        connection.process(Duration::from_millis(50))?;
        while let Ok(reply) = response.try_recv() {
            connection
                .send(reply)
                .map_err(|()| BrokerError::Transport)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn queued_replies_preserve_the_bus_call_serial() {
        let mut call = Message::new_method_call(
            DEVELOPMENT_BROKER_BUS,
            BROKER_PATH,
            BROKER_INTERFACE,
            "GetCoverage",
        )
        .unwrap();
        assert!(queued_message(&call).is_err());
        call.set_serial(27);
        let copy = queued_message(&call).unwrap();
        assert_eq!(
            copy.return_with_args(("reply",)).get_reply_serial(),
            Some(27)
        );
        assert_eq!(call.get_serial(), Some(27));
    }
}
