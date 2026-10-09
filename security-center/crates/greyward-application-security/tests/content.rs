use greyward_application_security::{CandidateContent, ContentError, content_generation};
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("greyward-content-{}-{time}", std::process::id()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn executable(&self, name: &str, content: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, content).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[test]
fn a_reused_path_does_not_change_the_inode_selected_by_descriptor() {
    let fixture = Fixture::new();
    let selected = fixture.executable("candidate", b"\x7fELFold selected bytes");
    let held = File::open(&selected).unwrap();
    let replacement = fixture.executable("replacement", b"\x7fELFother bytes");
    fs::rename(replacement, &selected).unwrap();
    let candidate = CandidateContent::capture(held.into(), deadline()).unwrap();
    assert_eq!(
        candidate.generation(),
        &content_generation(b"\x7fELFold selected bytes")
    );
    let new = CandidateContent::capture(File::open(selected).unwrap().into(), deadline()).unwrap();
    assert_ne!(candidate.generation(), new.generation());
}

#[test]
fn sender_descriptor_offset_cannot_substitute_a_partial_content_generation() {
    let fixture = Fixture::new();
    let path = fixture.executable("candidate", b"\x7fELFfull bytes");
    let mut held = File::open(path).unwrap();
    held.seek(SeekFrom::End(0)).unwrap();
    let candidate = CandidateContent::capture(held.into(), deadline()).unwrap();
    assert_eq!(
        candidate.generation(),
        &content_generation(b"\x7fELFfull bytes")
    );
}

#[test]
fn readonly_mode_does_not_make_a_previously_writable_inode_immutable() {
    let fixture = Fixture::new();
    let path = fixture.0.join("candidate");
    let mut writer = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    writer.write_all(b"\x7fELFmutable input").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
    let candidate =
        CandidateContent::capture(File::open(&path).unwrap().into(), deadline()).unwrap();
    writer
        .write_all(b"changed through retained descriptor")
        .unwrap();
    assert!(matches!(
        candidate.revalidate_object(),
        Err(ContentError::Changed)
    ));
    // It exposes no launch descriptor or immutable/grant-ready claim.
}

#[test]
fn directories_scripts_writable_descriptors_and_expiry_do_not_produce_candidates() {
    let fixture = Fixture::new();
    assert!(matches!(
        CandidateContent::capture(File::open(&fixture.0).unwrap().into(), deadline()),
        Err(ContentError::InvalidDescriptor)
    ));
    let script = fixture.executable("script", b"#!/bin/sh\nexit 0\n");
    assert!(matches!(
        CandidateContent::capture(File::open(script).unwrap().into(), deadline()),
        Err(ContentError::Unsupported)
    ));
    let path = fixture.executable("candidate", b"\x7fELFbytes");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let writable = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    assert!(matches!(
        CandidateContent::capture(writable.into(), deadline()),
        Err(ContentError::InvalidDescriptor)
    ));
    assert!(matches!(
        CandidateContent::capture(File::open(path).unwrap().into(), Instant::now()),
        Err(ContentError::Deadline)
    ));
}
