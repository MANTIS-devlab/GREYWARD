//! Bounded payload classification, without executing a downloaded runtime.
use crate::ContentError;
use std::fs::File;
use std::os::unix::fs::FileExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptInterpreter {
    Python,
    Bash,
    Shell,
}
impl ScriptInterpreter {
    pub fn path(self) -> &'static str {
        match self {
            Self::Python => "/usr/bin/python3",
            Self::Bash => "/usr/bin/bash",
            Self::Shell => "/usr/bin/sh",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    Elf,
    Script(ScriptInterpreter),
    AppImage { offset: u64 },
    Document,
}
impl PayloadKind {
    pub(crate) fn worker_value(self) -> String {
        match self {
            Self::Elf => "ELF".into(),
            Self::Script(ScriptInterpreter::Python) => "PYTHON".into(),
            Self::Script(_) => "SHELL".into(),
            Self::AppImage { offset } => format!("APPIMAGE:{offset}"),
            Self::Document => "DOCUMENT".into(),
        }
    }
}

pub(crate) fn classify(file: &File) -> Result<PayloadKind, ContentError> {
    let mut header = [0u8; 512];
    let length = file.read_at(&mut header, 0)?;
    let header = &header[..length];
    if header.starts_with(b"#!") {
        let first = header
            .split(|b| *b == b'\n')
            .next()
            .ok_or(ContentError::Unsupported)?;
        let words: Vec<_> = std::str::from_utf8(&first[2..])
            .map_err(|_| ContentError::Unsupported)?
            .split_whitespace()
            .collect();
        let name = match words.as_slice() {
            ["/usr/bin/env", name] => *name,
            ["/usr/bin/python3"] => "python3",
            ["/usr/bin/bash" | "/bin/bash"] => "bash",
            ["/usr/bin/sh" | "/bin/sh"] => "sh",
            _ => return Err(ContentError::Unsupported),
        };
        return Ok(PayloadKind::Script(match name {
            "python3" => ScriptInterpreter::Python,
            "bash" => ScriptInterpreter::Bash,
            "sh" => ScriptInterpreter::Shell,
            _ => return Err(ContentError::Unsupported),
        }));
    }
    if !header.starts_with(b"\x7fELF") {
        return Err(ContentError::Unsupported);
    }
    if header.get(8..11) == Some(b"AI\x02") {
        return Ok(PayloadKind::AppImage {
            offset: appimage_offset(file)?,
        });
    }
    if header.get(8..10) == Some(b"AI") {
        return Err(ContentError::Unsupported);
    }
    Ok(PayloadKind::Elf)
}
fn u16_at(value: &[u8], position: usize) -> Result<u16, ContentError> {
    Ok(u16::from_le_bytes(
        value
            .get(position..position + 2)
            .ok_or(ContentError::Unsupported)?
            .try_into()
            .map_err(|_| ContentError::Unsupported)?,
    ))
}
fn u64_at(value: &[u8], position: usize) -> Result<u64, ContentError> {
    Ok(u64::from_le_bytes(
        value
            .get(position..position + 8)
            .ok_or(ContentError::Unsupported)?
            .try_into()
            .map_err(|_| ContentError::Unsupported)?,
    ))
}
// Type-2 runtime layout: max(section-table end, last-section end), followed by
// a SquashFS v4 payload. Initial provider supports x86-64 little endian only.
fn appimage_offset(file: &File) -> Result<u64, ContentError> {
    let mut header = [0u8; 64];
    file.read_exact_at(&mut header, 0)?;
    if header[4..7] != [2, 1, 1] || u16_at(&header, 18)? != 62 {
        return Err(ContentError::Unsupported);
    }
    let table = u64_at(&header, 40)?;
    let size = u64::from(u16_at(&header, 58)?);
    let count = u64::from(u16_at(&header, 60)?);
    if table < 64 || size != 64 || !(1..=8192).contains(&count) {
        return Err(ContentError::Unsupported);
    }
    let end = table
        .checked_add(size.checked_mul(count).ok_or(ContentError::Unsupported)?)
        .ok_or(ContentError::Unsupported)?;
    if end > file.metadata()?.len() {
        return Err(ContentError::Unsupported);
    }
    let mut last = [0u8; 64];
    file.read_exact_at(&mut last, end - size)?;
    let section_end = u64_at(&last, 24)?
        .checked_add(u64_at(&last, 32)?)
        .ok_or(ContentError::Unsupported)?;
    let offset = end.max(section_end);
    let mut squash = [0u8; 96];
    file.read_exact_at(&mut squash, offset)?;
    let bytes = u64_at(&squash, 40)?;
    if &squash[..4] != b"hsqs"
        || u16_at(&squash, 28)? != 4
        || bytes < 96
        || offset
            .checked_add(bytes)
            .is_none_or(|end| end > file.metadata().map_or(0, |m| m.len()))
    {
        return Err(ContentError::Unsupported);
    }
    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    fn input(bytes: &[u8]) -> File {
        let path = std::env::temp_dir().join(format!(
            "guard-payload-{}-{}",
            std::process::id(),
            crate::framed_digest(&[bytes])
        ));
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(path).unwrap();
        file.write_all(bytes).unwrap();
        file
    }
    #[test]
    fn script_identity_selects_a_fixed_interpreter_without_shebang_options() {
        assert_eq!(
            classify(&input(b"#!/usr/bin/env python3\nprint('ok')\n")).unwrap(),
            PayloadKind::Script(ScriptInterpreter::Python)
        );
        for body in [
            b"#!/usr/bin/env -S python3 -c\n".as_slice(),
            b"#!/tmp/python3\n",
            b"#! /usr/bin/python3 -c\n",
        ] {
            assert!(classify(&input(body)).is_err());
        }
    }
    #[test]
    fn type_two_requires_bounded_squashfs_not_only_the_magic() {
        let mut image = vec![0u8; 224];
        image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        image[8..11].copy_from_slice(b"AI\x02");
        image[18..20].copy_from_slice(&62u16.to_le_bytes());
        image[40..48].copy_from_slice(&64u64.to_le_bytes());
        image[58..60].copy_from_slice(&64u16.to_le_bytes());
        image[60..62].copy_from_slice(&1u16.to_le_bytes());
        image[128..132].copy_from_slice(b"hsqs");
        image[156..158].copy_from_slice(&4u16.to_le_bytes());
        image[168..176].copy_from_slice(&96u64.to_le_bytes());
        assert_eq!(
            classify(&input(&image)).unwrap(),
            PayloadKind::AppImage { offset: 128 }
        );
        image[168..176].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(classify(&input(&image)).is_err());
    }
}
