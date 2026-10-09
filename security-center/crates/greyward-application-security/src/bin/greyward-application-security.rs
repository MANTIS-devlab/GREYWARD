//! No alternate storage path or arbitrary execution arguments are accepted.
use greyward_application_security::{EnrollmentPhase, PolicyStore, serve_enrolled, serve_reads};
fn main() {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let result = if arguments.is_empty() {
        PolicyStore::open_system()
            .map_err(|_| ())
            .and_then(|store| serve_reads(store).map_err(|_| ()))
    } else if arguments == ["--workflows"] {
        serve_enrolled().map_err(|_| ())
    } else if arguments.len() == 2 && arguments[0] == "--prepare-account" {
        arguments[1].to_str().ok_or(()).and_then(|name| {
            PolicyStore::open_system()
                .map_err(|_| ())?
                .prepare_account(name)
                .map_err(|_| ())
        })
    } else if arguments.len() == 3 && arguments[0] == "--advance-account" {
        let phase = match arguments[2].to_str() {
            Some("MAPPING_APPLIED") => Some(EnrollmentPhase::MappingApplied),
            Some("PENDING_SESSION") => Some(EnrollmentPhase::PendingSession),
            Some("ENROLLED") => Some(EnrollmentPhase::Enrolled),
            Some("RECOVERY_REQUIRED") => Some(EnrollmentPhase::RecoveryRequired),
            Some("UNENROLLED") => Some(EnrollmentPhase::Unenrolled),
            _ => None,
        };
        arguments[1].to_str().ok_or(()).and_then(|name| {
            PolicyStore::open_system()
                .map_err(|_| ())?
                .advance_account(name, phase.ok_or(())?)
                .map_err(|_| ())
        })
    } else {
        eprintln!("Application Security broker accepts only --workflows");
        std::process::exit(2);
    };
    if result.is_err() {
        eprintln!("Application Security broker unavailable; no enforcement fallback");
        std::process::exit(1);
    }
}
