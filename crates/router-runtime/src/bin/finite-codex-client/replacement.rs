//! Bounded replacement of one pre-existing approved file. No path comes from model text.
use router_adapter_api::{content_digest, is_digest, strict_json_limited};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat, fstat, openat, statat};
use serde::Deserialize;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

const MAX_STDOUT: usize = 65536;
const MAX_CONTENT: usize = 32768;
const MAX_EVENTS: usize = 256;

#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum Event {
    #[serde(rename = "thread.started")]
    ThreadStarted { thread_id: String },
    #[serde(rename = "turn.started")]
    TurnStarted,
    #[serde(rename = "item.started")]
    ItemStarted { item: Item },
    #[serde(rename = "item.updated")]
    ItemUpdated { item: Item },
    #[serde(rename = "item.completed")]
    ItemCompleted { item: Item },
    #[serde(rename = "turn.completed")]
    TurnCompleted { usage: Option<serde_json::Value> },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Item {
    id: String,
    #[serde(rename = "type")]
    kind: ItemKind,
    text: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ItemKind {
    AgentMessage,
    Reasoning,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Replacement {
    replacement: String,
}

fn replacement(stdout: &[u8]) -> Result<String, &'static str> {
    if stdout.is_empty() || stdout.len() > MAX_STDOUT {
        return Err("replacement.stdout.bound");
    }
    let text = std::str::from_utf8(stdout).map_err(|_| "replacement.stdout.utf8")?;
    if text.lines().count() > MAX_EVENTS {
        return Err("replacement.events.bound");
    }
    let (mut thread, mut turn, mut completed) = (false, false, false);
    let mut message = None;
    let mut message_id = None;
    for line in text.lines() {
        if completed {
            return Err("replacement.events.after_completion");
        }
        let value = strict_json_limited(line.as_bytes(), MAX_STDOUT)
            .map_err(|_| "replacement.event.json")?;
        let completed_item =
            value.get("type").and_then(serde_json::Value::as_str) == Some("item.completed");
        let event: Event = serde_json::from_value(value).map_err(|_| "replacement.event.shape")?;
        match event {
            Event::ThreadStarted { thread_id } => {
                if thread || turn || thread_id.is_empty() || thread_id.len() > 128 {
                    return Err("replacement.event.order");
                }
                thread = true;
            }
            Event::TurnStarted => {
                if !thread || turn {
                    return Err("replacement.event.order");
                }
                turn = true;
            }
            Event::TurnCompleted { usage } => {
                // These host-declared counts confer no accounting authority here.
                let _ = usage;
                if !turn || message.is_none() {
                    return Err("replacement.event.order");
                }
                completed = true;
            }
            Event::ItemStarted { item }
            | Event::ItemUpdated { item }
            | Event::ItemCompleted { item } => {
                if !turn || item.id.is_empty() || item.id.len() > 128 {
                    return Err("replacement.event.order");
                }
                if matches!(item.kind, ItemKind::AgentMessage) {
                    if message.is_some() || message_id.as_ref().is_some_and(|id| id != &item.id) {
                        return Err("replacement.message.ambiguous");
                    }
                    message_id = Some(item.id);
                    // Only an item.completed message may supply replacement bytes.
                    if completed_item {
                        message = Some(item.text.ok_or("replacement.message.text")?);
                    }
                }
            }
        }
    }
    if !completed {
        return Err("replacement.events.incomplete");
    }
    let text = message.ok_or("replacement.message.missing")?;
    let value =
        strict_json_limited(text.as_bytes(), MAX_STDOUT).map_err(|_| "replacement.payload.json")?;
    let body: Replacement =
        serde_json::from_value(value).map_err(|_| "replacement.payload.shape")?;
    if body.replacement.is_empty()
        || body.replacement.len() > MAX_CONTENT
        || body.replacement.contains('\0')
    {
        return Err("replacement.payload.bound");
    }
    Ok(body.replacement)
}

fn valid_file(stat: &Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
        && stat.st_nlink == 1
        && stat.st_uid == rustix::process::geteuid().as_raw()
        && stat.st_mode & 0o022 == 0
        && stat.st_size >= 0
        && stat.st_size <= 32768
}
fn same_identity(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_mode == b.st_mode
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_nlink == b.st_nlink
}
fn same_version(a: &Stat, b: &Stat) -> bool {
    same_identity(a, b)
        && a.st_size == b.st_size
        && a.st_mtime == b.st_mtime
        && a.st_mtime_nsec == b.st_mtime_nsec
        && a.st_ctime == b.st_ctime
        && a.st_ctime_nsec == b.st_ctime_nsec
}

/// Preflight refusals do not write. In-place I/O failures may leave a partial
/// replacement; the caller must treat them as failed, not as an atomic commit.
pub(super) fn apply(
    workspace: &Path,
    relative: &str,
    preimage: &str,
    stdout: &[u8],
) -> Result<(), &'static str> {
    if relative.is_empty()
        || relative.len() > 128
        || relative.starts_with('.')
        || !relative
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        || !is_digest(preimage)
    {
        return Err("replacement.binding");
    }
    let contents = replacement(stdout)?;
    let canonical = fs::canonicalize(workspace).map_err(|_| "replacement.workspace")?;
    if canonical.as_os_str() != workspace.as_os_str() {
        return Err("replacement.workspace");
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(workspace)
        .map_err(|_| "replacement.workspace.open")?;
    let directory_identity = fstat(&directory).map_err(|_| "replacement.workspace.stat")?;
    if FileType::from_raw_mode(directory_identity.st_mode) != FileType::Directory {
        return Err("replacement.workspace.type");
    }
    let descriptor = openat(
        &directory,
        relative,
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "replacement.file.open")?;
    let mut file = File::from(descriptor);
    let before = fstat(&file).map_err(|_| "replacement.file.stat")?;
    if !valid_file(&before) {
        return Err("replacement.file.type_or_authority");
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(32769)
        .read_to_end(&mut bytes)
        .map_err(|_| "replacement.file.read")?;
    if bytes.len() > MAX_CONTENT || content_digest(&bytes) != preimage {
        return Err("replacement.preimage");
    }
    let current = fstat(&file).map_err(|_| "replacement.file.stat")?;
    let named = statat(&directory, relative, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| "replacement.file.identity")?;
    let directory_named = statat(&directory, workspace, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| "replacement.workspace.identity")?;
    if !same_version(&before, &current)
        || !same_version(&before, &named)
        || !same_identity(&directory_identity, &directory_named)
    {
        return Err("replacement.file.identity");
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "replacement.file.seek")?;
    file.write_all(contents.as_bytes())
        .map_err(|_| "replacement.file.write")?;
    file.set_len(u64::try_from(contents.len()).map_err(|_| "replacement.payload.bound")?)
        .map_err(|_| "replacement.file.truncate")?;
    file.sync_all().map_err(|_| "replacement.file.sync")?;
    let written = fstat(&file).map_err(|_| "replacement.file.stat")?;
    let named = statat(&directory, relative, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| "replacement.file.identity")?;
    if !valid_file(&written) || !same_identity(&before, &written) || !same_version(&written, &named)
    {
        return Err("replacement.file.identity");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_adapter_api::content_digest;
    use serde_json::{Value, json};
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
        path::PathBuf,
    };
    struct Fixture {
        _temp: tempfile::TempDir,
        workspace: PathBuf,
        file: PathBuf,
        original: Vec<u8>,
    }
    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let workspace = temp.path().canonicalize().unwrap().join("workspace");
            fs::create_dir(&workspace).unwrap();
            let file = workspace.join("approved.rs");
            let original = b"original contents\n".to_vec();
            fs::write(&file, &original).unwrap();
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
            Self {
                _temp: temp,
                workspace,
                file,
                original,
            }
        }
        fn apply(&self, stream: &[u8]) -> Result<(), &'static str> {
            apply(
                &self.workspace,
                "approved.rs",
                &content_digest(&self.original),
                stream,
            )
        }
        fn unchanged(&self) {
            assert_eq!(fs::read(&self.file).unwrap(), self.original);
        }
    }
    fn message(text: &str) -> Value {
        json!({"type":"item.completed","item":{"id":"item_0","type":"agent_message","text":text}})
    }
    fn rows(text: &str) -> Vec<Value> {
        vec![
            json!({"type":"thread.started","thread_id":"authored"}),
            json!({"type":"turn.started"}),
            message(text),
            json!({"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}),
        ]
    }
    fn wire(rows: &[Value]) -> Vec<u8> {
        let mut raw = Vec::new();
        for row in rows {
            raw.extend(serde_json::to_vec(row).unwrap());
            raw.push(b'\n');
        }
        raw
    }
    fn stream(content: &str) -> Vec<u8> {
        wire(&rows(&json!({"replacement":content}).to_string()))
    }
    #[test]
    fn replaces_contents_of_only_the_existing_inode_and_truncates_its_tail() {
        let f = Fixture::new();
        let before = fs::metadata(&f.file).unwrap();
        let sibling = f.workspace.join("other.rs");
        fs::write(&sibling, b"keep").unwrap();
        f.apply(&stream("new\n")).unwrap();
        let after = fs::metadata(&f.file).unwrap();
        assert_eq!(fs::read(&f.file).unwrap(), b"new\n");
        assert_eq!(
            (before.dev(), before.ino(), before.mode()),
            (after.dev(), after.ino(), after.mode())
        );
        assert_eq!(fs::read(&sibling).unwrap(), b"keep");
    }
    #[test]
    fn incomplete_error_tool_and_post_terminal_events_never_write() {
        let text = json!({"replacement":"new"}).to_string();
        let original = rows(&text);
        let mut cases = vec![original[..3].to_vec()];
        for event in [
            json!({"type":"turn.failed"}),
            json!({"type":"unrecognized"}),
            json!({"type":"item.completed","item":{"id":"bad","type":"error","message":"failed"}}),
            json!({"type":"item.completed","item":{"id":"bad","type":"command_execution","command":"unsafe"}}),
        ] {
            let mut rows = original.clone();
            rows.insert(2, event);
            cases.push(rows);
        }
        let mut after = original.clone();
        after.push(json!({"type":"turn.started"}));
        cases.push(after);
        let mut duplicate = original.clone();
        duplicate.insert(3, message(&text));
        cases.push(duplicate);
        for rows in cases {
            let f = Fixture::new();
            assert!(f.apply(&wire(&rows)).is_err());
            f.unchanged();
        }
    }
    #[test]
    fn duplicate_keys_and_response_path_injection_are_refused() {
        for text in [
            "{\"replacement\":\"one\",\"replacement\":\"two\"}",
            "{\"replacement\":\"one\",\"path\":\"../private\"}",
            "{\"replacement\":1}",
        ] {
            let f = Fixture::new();
            assert!(f.apply(&wire(&rows(text))).is_err());
            f.unchanged();
        }
        let f = Fixture::new();
        let mut data =
            b"{\"type\":\"thread.started\",\"type\":\"turn.failed\",\"thread_id\":\"x\"}\n"
                .to_vec();
        data.extend(stream("new"));
        assert!(f.apply(&data).is_err());
        f.unchanged();
    }
    #[test]
    fn changed_preimage_is_preserved_without_truncation() {
        let f = Fixture::new();
        fs::write(&f.file, b"changed since approval").unwrap();
        assert!(f.apply(&stream("new")).is_err());
        assert_eq!(fs::read(&f.file).unwrap(), b"changed since approval");
    }
    #[test]
    fn symlink_and_hardlink_targets_are_never_modified() {
        for hard in [false, true] {
            let f = Fixture::new();
            let sibling = f.workspace.parent().unwrap().join("private-canary");
            fs::write(&sibling, &f.original).unwrap();
            fs::remove_file(&f.file).unwrap();
            if hard {
                fs::hard_link(&sibling, &f.file).unwrap();
            } else {
                symlink(&sibling, &f.file).unwrap();
            }
            assert!(f.apply(&stream("new")).is_err());
            assert_eq!(fs::read(sibling).unwrap(), f.original);
        }
    }
    #[test]
    fn fifo_is_refused_without_waiting_for_a_writer() {
        let f = Fixture::new();
        fs::remove_file(&f.file).unwrap();
        nix::unistd::mkfifo(
            &f.file,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        let start = std::time::Instant::now();
        assert!(f.apply(&stream("new")).is_err());
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }
    #[test]
    fn absent_or_group_writable_file_is_refused() {
        let f = Fixture::new();
        fs::set_permissions(&f.file, fs::Permissions::from_mode(0o620)).unwrap();
        assert!(f.apply(&stream("new")).is_err());
        f.unchanged();
        fs::remove_file(&f.file).unwrap();
        assert!(f.apply(&stream("new")).is_err());
        assert!(!f.file.exists());
    }
    #[test]
    fn response_and_preimage_byte_bounds_are_checked_before_writing() {
        for value in [
            String::new(),
            "x\0y".into(),
            "x".repeat(32769),
            "é".repeat(16385),
        ] {
            let f = Fixture::new();
            assert!(f.apply(&stream(&value)).is_err());
            f.unchanged();
        }
        let f = Fixture::new();
        assert!(f.apply(&vec![b' '; 65537]).is_err());
        f.unchanged();
        let f = Fixture::new();
        fs::write(&f.file, vec![b'o'; 32769]).unwrap();
        assert!(
            apply(
                &f.workspace,
                "approved.rs",
                &content_digest(&vec![b'o'; 32769]),
                &stream("new")
            )
            .is_err()
        );
        assert_eq!(fs::metadata(&f.file).unwrap().len(), 32769);
        let f = Fixture::new();
        let content = "x".repeat(32768);
        f.apply(&stream(&content)).unwrap();
        assert_eq!(fs::read_to_string(&f.file).unwrap(), content);
    }
    #[test]
    fn event_count_bound_still_allows_inert_reasoning_items() {
        let text = json!({"replacement":"new"}).to_string();
        let mut records = rows(&text);
        for i in 0..252 {
            records.insert(2,json!({"type":"item.completed","item":{"id":format!("reasoning{i}"),"type":"reasoning","text":"authored"}}));
        }
        let f = Fixture::new();
        f.apply(&wire(&records)).unwrap();
        records.insert(2,json!({"type":"item.completed","item":{"id":"extra","type":"reasoning","text":"authored"}}));
        let f = Fixture::new();
        assert!(f.apply(&wire(&records)).is_err());
        f.unchanged();
    }
    #[test]
    fn unsafe_names_and_noncanonical_workspace_are_refused() {
        let f = Fixture::new();
        for name in [
            "",
            ".hidden",
            "../approved.rs",
            "sub/approved.rs",
            "approved\\.rs",
            "é.rs",
            "line\n.rs",
        ] {
            assert!(
                apply(
                    &f.workspace,
                    name,
                    &content_digest(&f.original),
                    &stream("new")
                )
                .is_err()
            );
            f.unchanged();
        }
        assert!(
            apply(
                &f.workspace,
                &"x".repeat(129),
                &content_digest(&f.original),
                &stream("new")
            )
            .is_err()
        );
        let alias = f.workspace.parent().unwrap().join("alias");
        symlink(&f.workspace, &alias).unwrap();
        assert!(
            apply(
                &alias,
                "approved.rs",
                &content_digest(&f.original),
                &stream("new")
            )
            .is_err()
        );
        f.unchanged();
    }
    #[test]
    fn longest_approved_flat_name_and_nonempty_unicode_contents_work() {
        let f = Fixture::new();
        let name = "a".repeat(128);
        fs::rename(&f.file, f.workspace.join(&name)).unwrap();
        apply(
            &f.workspace,
            &name,
            &content_digest(&f.original),
            &stream("é\n"),
        )
        .unwrap();
        assert_eq!(fs::read_to_string(f.workspace.join(name)).unwrap(), "é\n");
    }
}
