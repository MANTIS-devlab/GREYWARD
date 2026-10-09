//! Descriptor-pinned host endpoint for a trusted nested compositor only.
use crate::{InstalledExecutable, IsolatedLaunchError};
use std::fs::{self, File};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::time::Instant;

pub(crate) fn host_display(uid: u32, deadline: Instant) -> Result<File, IsolatedLaunchError> {
    for path in ["/", "/run", "/run/user"] {
        let m = fs::symlink_metadata(path)?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(IsolatedLaunchError::Unavailable);
        }
    }
    let m = fs::symlink_metadata(format!("/run/user/{uid}"))?;
    if !m.is_dir() || m.uid() != uid || m.mode() & 0o077 != 0 {
        return Err(IsolatedLaunchError::Unavailable);
    }
    let descriptor = rustix::fs::open(
        format!("/run/user/{uid}/wayland-0"),
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let file = File::from(descriptor);
    let m = file.metadata()?;
    if !m.file_type().is_socket() || m.uid() != uid {
        return Err(IsolatedLaunchError::Unavailable);
    }
    let peer = UnixStream::connect(format!("/run/user/{uid}/wayland-0"))?;
    let credentials = rustix::net::sockopt::socket_peercred(&peer)?;
    let current = fs::symlink_metadata(format!("/run/user/{uid}/wayland-0"))?;
    if credentials.uid.as_raw() != uid || (m.dev(), m.ino()) != (current.dev(), current.ino()) {
        return Err(IsolatedLaunchError::Unavailable);
    }
    let pid = credentials.pid.as_raw_nonzero().get();
    let installed = InstalledExecutable::capture("/usr/bin/labwc", deadline)
        .map_err(|_| IsolatedLaunchError::Unavailable)?;
    let image = File::open(format!("/proc/{pid}/exe"))?;
    let expected = fs::metadata("/usr/bin/labwc")?;
    let actual = image.metadata()?;
    if (actual.dev(), actual.ino(), actual.uid(), actual.mode())
        != (
            expected.dev(),
            expected.ino(),
            expected.uid(),
            expected.mode(),
        )
    {
        return Err(IsolatedLaunchError::Unavailable);
    }
    installed
        .revalidate()
        .map_err(|_| IsolatedLaunchError::Unavailable)?;
    Ok(file)
}
