//! Fixed installed-file metadata provider. No verification scriptlets or changes.
use greyward_security_domain::InstalledExecutablePath;
use std::time::Instant;
use thiserror::Error;

pub const RPM_EXECUTABLE_QUERY: &str = "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SHA256HEADER}\t%{FILEDIGESTALGO}\n[%{FILENAMES}\t%{FILEDIGESTS}\t%{FILEMODES}\t%{FILEFLAGS}\n]";

#[derive(Debug, Error)]
pub enum RpmMetadataError {
    #[error("Installed package metadata collection is unavailable")]
    Unavailable,
    #[error("Installed package metadata deadline expired")]
    Deadline,
}

/// Query only the system RPM database with a fixed program/format and clean
/// environment. Output and pipes have real bounds, including inherited pipes.
/// The path type validates syntax; ancestry, hashing and provenance are separate.
/// # Errors
/// Missing/failed/oversized providers stay unavailable; expiry stays a failure.
pub fn read_installed_rpm_metadata(
    path: &InstalledExecutablePath,
    deadline: Instant,
) -> Result<Vec<u8>, RpmMetadataError> {
    let output =
        crate::provider_process::rpm_metadata_output(path.as_str(), deadline).map_err(|error| {
            if error.kind() == std::io::ErrorKind::TimedOut {
                RpmMetadataError::Deadline
            } else {
                RpmMetadataError::Unavailable
            }
        })?;
    if !output.status.success() || output.stdout.is_empty() || !output.stderr.is_empty() {
        return Err(RpmMetadataError::Unavailable);
    }
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn an_expired_metadata_query_never_becomes_an_empty_inventory() {
        let path = InstalledExecutablePath::try_from("/usr/bin/cat").unwrap();
        assert!(matches!(
            read_installed_rpm_metadata(&path, Instant::now()),
            Err(RpmMetadataError::Deadline)
        ));
    }
}
