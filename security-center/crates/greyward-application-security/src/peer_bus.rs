//! Resolve bus-stamped unique senders through the actual system bus daemon.
//! No frontend, claimed UI identity or group membership authorizes a change.
use crate::{BusPeerCredentials, ExecutionError, ExecutionHandle};
use dbus::arg::{PropMap, prop_cast};
use dbus::blocking::Connection;
use dbus::strings::BusName;
use std::fs::{self, File};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PeerError {
    #[error("Bus peer credentials or process descriptor are unavailable")]
    Unavailable,
    #[error("Peer identity resolution deadline expired")]
    Deadline,
    #[error(transparent)]
    Bus(#[from] dbus::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Execution(#[from] ExecutionError),
}

pub struct SystemPeerResolver {
    connection: Connection,
}

pub(crate) fn system_connection() -> Result<Connection, PeerError> {
    for path in ["/run", "/run/dbus"] {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(PeerError::Unavailable);
        }
    }
    let socket = fs::symlink_metadata("/run/dbus/system_bus_socket")?;
    if !socket.file_type().is_socket() || socket.uid() != 0 {
        return Err(PeerError::Unavailable);
    }
    Ok(Connection::new_address(
        "unix:path=/run/dbus/system_bus_socket",
    )?)
}

impl SystemPeerResolver {
    /// Use the system bus; there is no session-bus or environment-selected peer
    /// authority fallback. Verify the fixed root-owned socket and parents.
    /// # Errors
    /// Unavailable system bus remains an error.
    pub fn connect() -> Result<Self, PeerError> {
        Ok(Self {
            connection: system_connection()?,
        })
    }

    fn credentials(&self, sender: &BusName<'_>, deadline: Instant) -> Result<PropMap, PeerError> {
        let wait = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(PeerError::Deadline)?;
        let proxy = self.connection.with_proxy(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            wait.min(Duration::from_secs(2)),
        );
        let (credentials,): (PropMap,) = proxy.method_call(
            "org.freedesktop.DBus",
            "GetConnectionCredentials",
            (sender.to_string(),),
        )?;
        Ok(credentials)
    }

    /// Accept only the message's bus-stamped unique sender, never a JSON field.
    /// This establishes execution evidence, not authorization or app provenance.
    /// # Errors
    /// Missing/exited peers, forged well-known names and inconsistent credentials
    /// cannot acquire a handle. Missing `ProcessFD` is explicitly unavailable.
    pub fn resolve(&self, sender: &BusName<'_>) -> Result<ExecutionHandle, PeerError> {
        self.resolve_until(sender, Instant::now() + Duration::from_secs(6))
    }

    /// Resolve within the broker operation's monotonic deadline.
    /// # Errors
    /// Expired deadlines and incomplete/changing peer evidence are refused.
    pub fn resolve_until(
        &self,
        sender: &BusName<'_>,
        deadline: Instant,
    ) -> Result<ExecutionHandle, PeerError> {
        if !sender.starts_with(':') {
            return Err(PeerError::Unavailable);
        }
        let values = self.credentials(sender, deadline)?;
        let uid = *prop_cast::<u32>(&values, "UnixUserID").ok_or(PeerError::Unavailable)?;
        let pid = *prop_cast::<u32>(&values, "ProcessID").ok_or(PeerError::Unavailable)?;
        let label =
            prop_cast::<Vec<u8>>(&values, "LinuxSecurityLabel").ok_or(PeerError::Unavailable)?;
        if label.len() > 1024 {
            return Err(PeerError::Unavailable);
        }
        let label = String::from_utf8(label.clone()).map_err(|_| PeerError::Unavailable)?;
        // libdbus's dynamic variant reader represents a Unix FD as File.
        let descriptor = prop_cast::<File>(&values, "ProcessFD").ok_or(PeerError::Unavailable)?;
        let handle = ExecutionHandle::capture(BusPeerCredentials {
            uid,
            pid,
            selinux_label: label.clone(),
            process_fd: descriptor.try_clone()?.into(),
        })?;
        // The unique connection must still exist and retain its kernel identity.
        let current = self.credentials(sender, deadline)?;
        if prop_cast::<u32>(&current, "UnixUserID") != Some(&uid)
            || prop_cast::<u32>(&current, "ProcessID") != Some(&pid)
            || prop_cast::<Vec<u8>>(&current, "LinuxSecurityLabel")
                .is_none_or(|value| value.as_slice() != label.as_bytes())
        {
            return Err(PeerError::Unavailable);
        }
        handle.revalidate()?;
        if Instant::now() >= deadline {
            return Err(PeerError::Deadline);
        }
        Ok(handle)
    }
}
