//! Fixed typed client for Guard. One connection retains execution ownership of
//! its reviews; a later process cannot apply another process's preview.
use crate::{BROKER_BUS, BROKER_INTERFACE, BROKER_PATH, DEVELOPMENT_BROKER_BUS, WorkflowPreview};
use dbus::blocking::Connection;
use greyward_security_domain::{
    ApplicationCoverage, OperationOutcome, OperationResult, ProtectedResourcePage,
    SecurityReference,
};
use std::fs::File;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GuardClientError {
    #[error("The typed Guard provider is unavailable; no unrestricted fallback")]
    Unavailable,
    #[error("The authorized operation did not complete with verified readback")]
    Failed,
    #[error(transparent)]
    Bus(#[from] dbus::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub struct GuardClient {
    connection: Connection,
    destination: &'static str,
    owner: String,
}
impl GuardClient {
    /// # Errors
    /// Returns an error if the pinned provider changes or its D-Bus call fails.
    pub fn session_lock(&self, request: bool) -> Result<bool, GuardClientError> {
        self.current()?;
        let method = if request {
            "RequestSessionLock"
        } else {
            "GetSessionLock"
        };
        let (result,): (bool,) = self.proxy().method_call(BROKER_INTERFACE, method, ())?;
        self.current()?;
        Ok(result)
    }
    /// Admit only the real freshly authenticated local session leader.
    ///
    /// # Errors
    /// Returns an error on provider change, failed admission or a D-Bus failure.
    pub fn start_desktop(&self) -> Result<(), GuardClientError> {
        self.current()?;
        let (started,): (bool,) = self
            .proxy()
            .method_call(BROKER_INTERFACE, "StartDesktop", ())?;
        self.current()?;
        if !started {
            return Err(GuardClientError::Unavailable);
        }
        Ok(())
    }
    /// # Errors
    /// Fixed system bus and root-owned provider, without environment routing.
    pub fn connect(development: bool) -> Result<Self, GuardClientError> {
        let connection =
            crate::peer_bus::system_connection().map_err(|_| GuardClientError::Unavailable)?;
        let destination = if development {
            DEVELOPMENT_BROKER_BUS
        } else {
            BROKER_BUS
        };
        let proxy = connection.with_proxy(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            Duration::from_secs(2),
        );
        let (owner,): (String,) =
            proxy.method_call("org.freedesktop.DBus", "GetNameOwner", (destination,))?;
        let (uid,): (u32,) =
            proxy.method_call("org.freedesktop.DBus", "GetConnectionUnixUser", (&owner,))?;
        if uid != 0 || !owner.starts_with(':') {
            return Err(GuardClientError::Unavailable);
        }
        Ok(Self {
            connection,
            destination,
            owner,
        })
    }
    pub fn unique_name(&self) -> String {
        self.connection.unique_name().to_string()
    }
    fn current(&self) -> Result<(), GuardClientError> {
        let proxy = self.connection.with_proxy(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            Duration::from_secs(2),
        );
        let (owner,): (String,) =
            proxy.method_call("org.freedesktop.DBus", "GetNameOwner", (self.destination,))?;
        if owner != self.owner {
            return Err(GuardClientError::Unavailable);
        }
        Ok(())
    }
    fn proxy(&self) -> dbus::blocking::Proxy<'_, &Connection> {
        self.connection
            .with_proxy(&self.owner, BROKER_PATH, Duration::from_secs(6))
    }
    fn json<T: serde::de::DeserializeOwned>(value: &str) -> Result<T, GuardClientError> {
        if value.len() > 256 * 1024 {
            return Err(GuardClientError::Unavailable);
        }
        Ok(serde_json::from_str(value)?)
    }
    /// # Errors
    /// Resource metadata cannot be treated as verified effective protection.
    pub fn resources(&self) -> Result<ProtectedResourcePage, GuardClientError> {
        self.current()?;
        let (value,): (String,) = self.proxy().method_call(
            BROKER_INTERFACE,
            "ListProtectedResources",
            (100_u32, false, 0_u64, ""),
        )?;
        self.current()?;
        Self::json(&value)
    }
    /// # Errors
    /// Unknown/missing coverage stays explicit; no profile is inferred here.
    pub fn coverage(&self) -> Result<ApplicationCoverage, GuardClientError> {
        self.current()?;
        let (value,): (String,) = self
            .proxy()
            .method_call(BROKER_INTERFACE, "GetCoverage", ())?;
        self.current()?;
        Self::json(&value)
    }
    fn preview(&self, value: &str) -> Result<WorkflowPreview, GuardClientError> {
        self.current()?;
        let preview: WorkflowPreview = Self::json(value)?;
        preview
            .validate()
            .map_err(|_| GuardClientError::Unavailable)?;
        Ok(preview)
    }
    /// # Errors
    /// Pass an already-held `O_PATH` directory, never a root pathname to reopen.
    pub fn preview_registration(
        &self,
        directory: File,
        category: &str,
        label: &str,
        revision: u64,
    ) -> Result<WorkflowPreview, GuardClientError> {
        self.current()?;
        let (value,): (String,) = self.proxy().method_call(
            BROKER_INTERFACE,
            "PreviewResourceRegistration",
            (directory, category, label, revision),
        )?;
        self.preview(&value)
    }
    /// # Errors
    /// Root provider validates installed code; the path is selection, not trust.
    pub fn preview_grant(
        &self,
        path: &str,
        resources: &[SecurityReference],
        revision: u64,
    ) -> Result<WorkflowPreview, GuardClientError> {
        self.current()?;
        let resources: Vec<&str> = resources.iter().map(SecurityReference::as_str).collect();
        let (value,): (String,) = self.proxy().method_call(
            BROKER_INTERFACE,
            "PreviewPolicyChange",
            (path, resources, revision),
        )?;
        self.preview(&value)
    }
    /// # Errors
    /// Stale/foreign installation, grant or policy cannot acquire a revoke handle.
    pub fn preview_revoke(
        &self,
        grant: &SecurityReference,
        path: &str,
        revision: u64,
    ) -> Result<WorkflowPreview, GuardClientError> {
        self.current()?;
        let (value,): (String,) = self.proxy().method_call(
            BROKER_INTERFACE,
            "PreviewGrantRevocation",
            (grant.as_str(), path, revision),
        )?;
        self.preview(&value)
    }
    /// # Errors
    /// Submission is not completion. The same peer must query actual readback.
    pub fn apply(
        &self,
        operation: &SecurityReference,
        interactive: bool,
    ) -> Result<OperationResult, GuardClientError> {
        self.current()?;
        let (value,): (String,) = self.proxy().method_call(
            BROKER_INTERFACE,
            "ApplyPolicyChange",
            (operation.as_str(), interactive),
        )?;
        self.current()?;
        Self::json(&value)
    }
    /// # Errors
    /// Owner/process mismatch, provider restart and malformed outcomes refuse.
    pub fn operation(
        &self,
        operation: &SecurityReference,
    ) -> Result<OperationResult, GuardClientError> {
        self.current()?;
        let (value,): (String,) =
            self.proxy()
                .method_call(BROKER_INTERFACE, "GetOperation", (operation.as_str(),))?;
        self.current()?;
        let result: OperationResult = Self::json(&value)?;
        result
            .validate()
            .map_err(|_| GuardClientError::Unavailable)?;
        if &result.operation_ref != operation {
            return Err(GuardClientError::Unavailable);
        }
        Ok(result)
    }
    /// # Errors
    /// A client deadline is an uncertain outcome, never a cancellation claim.
    pub fn wait_operation(
        &self,
        operation: &SecurityReference,
        deadline: Instant,
    ) -> Result<OperationResult, GuardClientError> {
        loop {
            if Instant::now() >= deadline {
                return Err(GuardClientError::Unavailable);
            }
            let result = self.operation(operation)?;
            match result.outcome {
                OperationOutcome::Completed => return Ok(result),
                OperationOutcome::Failed
                | OperationOutcome::Cancelled
                | OperationOutcome::Expired => return Err(GuardClientError::Failed),
                _ => std::thread::sleep(Duration::from_millis(100)),
            }
        }
    }
    /// # Errors
    /// Only a current reviewed grant can prepare the immutable installed code.
    pub fn prepare_launch(
        &self,
        grant: &SecurityReference,
        path: &str,
        arguments: Vec<String>,
    ) -> Result<SecurityReference, GuardClientError> {
        self.current()?;
        let (value,): (String,) = self.proxy().method_call(
            BROKER_INTERFACE,
            "PrepareLaunch",
            (grant.as_str(), path, arguments),
        )?;
        self.current()?;
        let reference =
            SecurityReference::try_from(value).map_err(|_| GuardClientError::Unavailable)?;
        if reference.namespace() != "launch" {
            return Err(GuardClientError::Unavailable);
        }
        Ok(reference)
    }
    /// # Errors
    /// Pass only a held `O_PATH` code selection. Unsupported primitives or inputs
    /// refuse; there is no path reopening or unrestricted fallback in the client.
    pub fn prepare_isolated(
        &self,
        candidate: File,
        arguments: Vec<String>,
    ) -> Result<SecurityReference, GuardClientError> {
        self.prepare_selected(candidate, arguments, false)
    }
    /// # Errors
    /// Refuse unless a verified enrolled compositor and private display helper
    /// are available; never connect the application to the host display.
    pub fn prepare_graphical(
        &self,
        candidate: File,
        arguments: Vec<String>,
    ) -> Result<SecurityReference, GuardClientError> {
        self.prepare_selected(candidate, arguments, true)
    }
    fn prepare_selected(
        &self,
        candidate: File,
        arguments: Vec<String>,
        graphical: bool,
    ) -> Result<SecurityReference, GuardClientError> {
        self.current()?;
        let (value,): (String,) = self.proxy().method_call(
            BROKER_INTERFACE,
            if graphical {
                "PrepareGraphicalLaunch"
            } else {
                "PrepareIsolatedLaunch"
            },
            (candidate, arguments),
        )?;
        self.current()?;
        let reference =
            SecurityReference::try_from(value).map_err(|_| GuardClientError::Unavailable)?;
        if reference.namespace() != "launch" {
            return Err(GuardClientError::Unavailable);
        }
        Ok(reference)
    }
    /// # Errors
    /// A held ordinary document is bound to a validated installed handler.
    pub fn prepare_document(
        &self,
        document: File,
        handler: &str,
        arguments: Vec<String>,
        graphical: bool,
    ) -> Result<SecurityReference, GuardClientError> {
        self.current()?;
        let (value,): (String,) = self.proxy().method_call(
            BROKER_INTERFACE,
            "PrepareSelectedDocumentLaunch",
            (document, handler, arguments, graphical),
        )?;
        self.current()?;
        let reference =
            SecurityReference::try_from(value).map_err(|_| GuardClientError::Unavailable)?;
        if reference.namespace() != "launch" {
            return Err(GuardClientError::Unavailable);
        }
        Ok(reference)
    }
    /// # Errors
    /// A one-shot owned preparation supplies only user-workload stdio streams.
    pub fn start_launch(
        &self,
        launch: &SecurityReference,
    ) -> Result<(File, File, File), GuardClientError> {
        self.current()?;
        let streams = self.proxy().method_call(
            BROKER_INTERFACE,
            "StartPreparedLaunch",
            (launch.as_str(),),
        )?;
        self.current()?;
        Ok(streams)
    }
    /// # Errors
    /// Exit code is separate from protection evidence. Deadline/provider loss
    /// never becomes a successful launch or a cancellation acknowledgment.
    pub fn wait_launch(
        &self,
        launch: &SecurityReference,
        deadline: Instant,
    ) -> Result<i32, GuardClientError> {
        loop {
            if Instant::now() >= deadline {
                return Err(GuardClientError::Unavailable);
            }
            self.current()?;
            let (finished, exit): (bool, i32) =
                self.proxy()
                    .method_call(BROKER_INTERFACE, "GetLaunch", (launch.as_str(),))?;
            if finished {
                return Ok(exit);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}
