//! Bounded, symlink-refusing directory walk. Nothing here follows a link,
//! executes a file or reads outside the explicit source directory.
use crate::{RefusalReason, RefusedFile};
use std::{
    fs,
    io::Read,
    path::{Component, Path},
};

pub(crate) const MAX_FILE_BYTES: u64 = 256 * 1024;
pub(crate) const MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RELATIVE_PATH_BYTES: usize = 512;
const MAX_DEPTH: usize = 4;
const MAX_DIR_ENTRIES: usize = 512;
const MAX_VISITED: usize = 4096;
const SCRIPT_EXTENSIONS: &[&str] = &[
    "sh", "bash", "zsh", "fish", "py", "rb", "pl", "js", "mjs", "cjs", "ts", "ps1", "bat", "cmd",
    "lua", "php",
];

pub(crate) struct Scanned {
    pub relative: String,
    pub agent: bool,
    pub bytes: Vec<u8>,
}
pub(crate) struct Scan {
    pub files: Vec<Scanned>,
    pub refused: Vec<RefusedFile>,
}
struct Counters {
    visited: usize,
    total: u64,
    max_total: u64,
}
pub(crate) enum ScanFailure {
    Source(&'static str),
    Limit(&'static str),
    Io(&'static str),
}

pub(crate) fn scan(root: &Path) -> Result<Scan, ScanFailure> {
    scan_with(root, MAX_TOTAL_BYTES)
}

/// The directory walk checks each level with `lstat` and reads the final file
/// with `O_NOFOLLOW`. A concurrent writer who swaps an intermediate directory
/// for a link between those steps is out of scope: the source must not change
/// during an import (see docs/importer.md).
pub(crate) fn scan_with(root: &Path, max_total: u64) -> Result<Scan, ScanFailure> {
    if root
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(ScanFailure::Source("parent traversal in source directory"));
    }
    let meta = fs::symlink_metadata(root).map_err(|_| ScanFailure::Io("inspect source"))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(ScanFailure::Source("source must be a real directory"));
    }
    let mut scan = Scan {
        files: Vec::new(),
        refused: Vec::new(),
    };
    let mut counters = Counters {
        visited: 0,
        total: 0,
        max_total,
    };
    for (name, agent) in [("agents", true), ("skills", false)] {
        let path = root.join(name);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                refuse(&mut scan, name, RefusalReason::Symlink)
            }
            Ok(meta) if meta.is_dir() => walk(&path, name, agent, 1, &mut counters, &mut scan)?,
            Ok(_) => refuse(&mut scan, name, RefusalReason::NotRegular),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(ScanFailure::Io("inspect source")),
        }
    }
    scan.files.sort_by(|a, b| a.relative.cmp(&b.relative));
    scan.refused.sort();
    Ok(scan)
}

fn refuse(scan: &mut Scan, path: &str, reason: RefusalReason) {
    scan.refused.push(RefusedFile {
        path: crate::escape_path(path),
        reason,
    });
}

fn walk(
    dir: &Path,
    relative: &str,
    agent: bool,
    depth: usize,
    counters: &mut Counters,
    scan: &mut Scan,
) -> Result<(), ScanFailure> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(dir).map_err(|_| ScanFailure::Io("read directory"))? {
        let entry = entry.map_err(|_| ScanFailure::Io("read directory"))?;
        if entries.len() >= MAX_DIR_ENTRIES {
            return Err(ScanFailure::Limit("directory entries"));
        }
        entries.push(entry);
    }
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        counters.visited += 1;
        if counters.visited > MAX_VISITED {
            return Err(ScanFailure::Limit("visited entries"));
        }
        let lossy = entry.file_name().to_string_lossy().into_owned();
        let child = format!("{relative}/{lossy}");
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            refuse(scan, &child, RefusalReason::UnsafePath);
            continue;
        };
        if name.is_empty()
            || name.contains(['\\', '/'])
            || name == "."
            || name == ".."
            || child.len() > MAX_RELATIVE_PATH_BYTES
            || name
                .chars()
                .any(|c| c.is_control() || router_catalog::is_bidi_control(c))
        {
            refuse(scan, &child, RefusalReason::UnsafePath);
            continue;
        }
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|_| ScanFailure::Io("inspect entry"))?;
        let kind = meta.file_type();
        if kind.is_symlink() {
            refuse(scan, &child, RefusalReason::Symlink);
        } else if kind.is_dir() {
            if depth >= MAX_DEPTH {
                return Err(ScanFailure::Limit("directory depth"));
            }
            walk(&path, &child, agent, depth + 1, counters, scan)?;
        } else if !kind.is_file() {
            refuse(scan, &child, RefusalReason::NotRegular);
        } else if is_executable(&meta) || is_script_name(&name) {
            refuse(scan, &child, RefusalReason::ExecutableScript);
        } else if !name.ends_with(".md") {
            refuse(scan, &child, RefusalReason::UnsupportedFile);
        } else if meta.len() > MAX_FILE_BYTES {
            refuse(scan, &child, RefusalReason::TooLarge);
        } else {
            match read_regular(&path, &meta) {
                Some(bytes) if bytes.len() as u64 <= MAX_FILE_BYTES => {
                    counters.total += bytes.len() as u64;
                    if counters.total > counters.max_total {
                        return Err(ScanFailure::Limit("total bytes"));
                    }
                    scan.files.push(Scanned {
                        relative: child,
                        agent,
                        bytes,
                    });
                }
                Some(_) => refuse(scan, &child, RefusalReason::TooLarge),
                None => refuse(scan, &child, RefusalReason::Unreadable),
            }
        }
    }
    Ok(())
}

fn is_script_name(name: &str) -> bool {
    Path::new(name)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            SCRIPT_EXTENSIONS
                .iter()
                .any(|s| ext.eq_ignore_ascii_case(s))
        })
}

#[cfg(unix)]
fn is_executable(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}
#[cfg(not(unix))]
fn is_executable(_: &fs::Metadata) -> bool {
    false
}

/// Opens the path and confirms it is still the regular file that was inspected,
/// so a link swapped in after the `lstat` is not followed.
pub(crate) fn read_regular(path: &Path, inspected: &fs::Metadata) -> Option<Vec<u8>> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // NONBLOCK: a FIFO swapped in after the lstat must not hang the import.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).ok()?;
    let opened = file.metadata().ok()?;
    if !opened.is_file() || !same_file(inspected, &opened) {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

#[cfg(unix)]
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}
#[cfg(not(unix))]
fn same_file(_: &fs::Metadata, _: &fs::Metadata) -> bool {
    true
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{process::Command, sync::mpsc, time::Duration};

    #[test]
    fn a_fifo_swapped_in_after_inspection_is_refused_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let regular = dir.path().join("a.md");
        fs::write(&regular, b"x").unwrap();
        let inspected = fs::symlink_metadata(&regular).unwrap();
        let fifo = dir.path().join("b.md");
        assert!(
            Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(read_regular(&fifo, &inspected));
        });
        let result = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("opening a FIFO must not block");
        assert!(result.is_none());
    }
}
