//! Inert file/budget policy candidate. The caller owns all process isolation.
use router_adapter_api::content_digest;
use rustix::fs::{AtFlags, Mode, OFlags, open, openat, statat};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Instant,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_calls: u32,
    pub max_file_bytes: usize,
    pub max_output_bytes: usize,
    pub max_total_output_bytes: usize,
    pub max_exec_ms: u64,
    pub max_total_exec_ms: u64,
    pub max_session_ms: u64,
    pub max_scratch_entries: usize,
    pub max_scratch_bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub termination: String,
    pub truncated: bool,
    pub elapsed_ms: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct Pin {
    dev: u64,
    ino: u64,
    hash: String,
    bytes: u64,
    mode: u32,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Scratch {
    files: BTreeMap<String, Pin>,
    dirs: BTreeMap<String, (u64, u64)>,
    bytes: u64,
    entries: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalEntry {
    pub index: u32,
    pub tool: String,
    pub status: String,
    pub argument_sha256: Option<String>,
    pub output_bytes: usize,
    pub exit_code: Option<i32>,
    pub elapsed_ms: u64,
    pub truncated: bool,
    pub file_sha256: Option<String>,
}
struct Directory {
    path: PathBuf,
    file: File,
    identity: (u64, u64),
}

fn directory(path: &Path) -> Result<Directory, &'static str> {
    if path == Path::new("/") {
        return Err("policy.root");
    }
    let file = File::from(
        open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "policy.directory")?,
    );
    let meta = file.metadata().map_err(|_| "policy.metadata")?;
    if !meta.is_dir()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o7022 != 0
    {
        return Err("policy.directory_owner");
    }
    Ok(Directory {
        path: fs::canonicalize(path).map_err(|_| "policy.canonical")?,
        identity: (meta.dev(), meta.ino()),
        file,
    })
}
impl Directory {
    fn verify(&self) -> Result<(), &'static str> {
        let meta = fs::symlink_metadata(&self.path).map_err(|_| "policy.directory_changed")?;
        if !meta.is_dir()
            || (meta.dev(), meta.ino()) != self.identity
            || meta.uid() != rustix::process::geteuid().as_raw()
            || meta.mode() & 0o7022 != 0
        {
            return Err("policy.directory_changed");
        }
        Ok(())
    }
}
fn flat(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn key_args(value: &Value, required: &[&str], optional: &[&str]) -> Result<(), &'static str> {
    let fields = value.as_object().ok_or("policy.arguments")?;
    if required.iter().any(|key| !fields.contains_key(*key))
        || fields
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err("policy.arguments");
    }
    Ok(())
}
fn absent(dir: &File, name: &str) -> Result<(), &'static str> {
    match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        _ => Err("policy.target_exists"),
    }
}
fn snapshot(file: &mut File, bound: u64) -> Result<Pin, &'static str> {
    let before = file.metadata().map_err(|_| "policy.metadata")?;
    if !before.is_file()
        || before.nlink() != 1
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.mode() & 0o7022 != 0
        || before.len() > bound
    {
        return Err("policy.file_type_or_bound");
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| "policy.seek")?;
    let mut raw = Vec::new();
    file.take(bound + 1)
        .read_to_end(&mut raw)
        .map_err(|_| "policy.read")?;
    let after = file.metadata().map_err(|_| "policy.metadata")?;
    if raw.len() as u64 > bound
        || before.len() != raw.len() as u64
        || before.len() != after.len()
        || (before.dev(), before.ino(), before.nlink(), before.mode())
            != (after.dev(), after.ino(), after.nlink(), after.mode())
    {
        return Err("policy.file_changed");
    }
    Ok(Pin {
        dev: after.dev(),
        ino: after.ino(),
        hash: content_digest(&raw),
        bytes: raw.len() as u64,
        mode: after.mode(),
    })
}
fn file_at(dir: &File, name: &str, write: bool) -> Result<File, &'static str> {
    let access = if write { OFlags::RDWR } else { OFlags::RDONLY };
    openat(
        dir,
        name,
        access | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| "policy.file_open")
}
fn scan_scratch(root: &Directory, limits: &Limits) -> Result<Scratch, &'static str> {
    fn walk(
        dir: &File,
        prefix: &str,
        depth: usize,
        state: &mut Scratch,
        limits: &Limits,
    ) -> Result<(), &'static str> {
        if depth > 4 {
            return Err("policy.scratch_depth");
        }
        for entry in rustix::fs::Dir::read_from(dir).map_err(|_| "policy.scratch_inventory")? {
            let entry = entry.map_err(|_| "policy.scratch_inventory")?;
            let name = entry
                .file_name()
                .to_str()
                .map_err(|_| "policy.scratch_name")?
                .to_owned();
            if matches!(name.as_str(), "." | "..") {
                continue;
            }
            state.entries += 1;
            if state.entries > limits.max_scratch_entries {
                return Err("policy.scratch_entries");
            }
            if name.is_empty()
                || name.len() > 255
                || name.chars().any(char::is_control)
                || name.contains('/')
            {
                return Err("policy.scratch_name");
            }
            let fd = File::from(
                openat(
                    dir,
                    name.as_str(),
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| "policy.scratch_open")?,
            );
            let meta = fd.metadata().map_err(|_| "policy.metadata")?;
            if meta.uid() != rustix::process::geteuid().as_raw() {
                return Err("policy.scratch_owner");
            }
            let relative = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if meta.is_dir() {
                state
                    .dirs
                    .insert(relative.clone(), (meta.dev(), meta.ino()));
                walk(&fd, &relative, depth + 1, state, limits)?;
            } else {
                let mut file = fd;
                let pin = snapshot(&mut file, limits.max_scratch_bytes)?;
                state.bytes = state
                    .bytes
                    .checked_add(pin.bytes)
                    .ok_or("policy.scratch_bytes")?;
                if state.bytes > limits.max_scratch_bytes {
                    return Err("policy.scratch_bytes");
                }
                state.files.insert(relative, pin);
            }
        }
        Ok(())
    }
    root.verify()?;
    let mut state = Scratch::default();
    walk(&root.file, "", 0, &mut state, limits)?;
    root.verify()?;
    Ok(state)
}

pub struct Engine {
    root: Directory,
    scratch: Directory,
    public: BTreeMap<String, String>,
    immutable: BTreeMap<String, Pin>,
    _pinned_public: Vec<File>,
    _pinned_output: Option<File>,
    output: String,
    target: Option<Pin>,
    scratch_state: Scratch,
    limits: Limits,
    calls: u32,
    total_output: usize,
    exec_ms: u64,
    started: Instant,
    halted: bool,
    journal: Vec<JournalEntry>,
}
fn argument_digest(value: &Value) -> Result<String, &'static str> {
    let mut pending = vec![(value, 0)];
    let mut nodes = 0;
    while let Some((value, depth)) = pending.pop() {
        nodes += 1;
        if depth > 16 || nodes > 256 {
            return Err("policy.input_bound");
        }
        match value {
            Value::Array(values) => {
                if values.len() + pending.len() > 256 {
                    return Err("policy.input_bound");
                }
                pending.extend(values.iter().map(|v| (v, depth + 1)));
            }
            Value::Object(values) => {
                if values.len() + pending.len() > 256 {
                    return Err("policy.input_bound");
                }
                pending.extend(values.values().map(|v| (v, depth + 1)));
            }
            _ => {}
        }
    }
    struct Bounded(Vec<u8>);
    impl Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self
                .0
                .len()
                .checked_add(bytes.len())
                .is_none_or(|n| n > 65536)
            {
                return Err(std::io::Error::other("bound"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut out = Bounded(vec![]);
    serde_json::to_writer(&mut out, value).map_err(|_| "policy.input_bound")?;
    Ok(content_digest(&out.0))
}
impl Engine {
    fn record(&self, name: &str, digest: Option<String>) -> JournalEntry {
        JournalEntry {
            index: self.calls + 1,
            tool: if matches!(name, "read_file" | "write_file" | "exec") {
                name.into()
            } else {
                "unknown".into()
            },
            status: "refused".into(),
            argument_sha256: digest,
            output_bytes: 0,
            exit_code: None,
            elapsed_ms: 0,
            truncated: false,
            file_sha256: None,
        }
    }
    fn append(&mut self, record: JournalEntry) {
        if self.journal.len() < self.limits.max_calls as usize + 1 {
            self.journal.push(record);
        } else {
            self.halted = true;
        }
    }
    pub fn open(
        root: &Path,
        scratch: &Path,
        public: BTreeMap<String, String>,
        output: &str,
        preimage: Option<String>,
        limits: Limits,
    ) -> Result<Self, &'static str> {
        if !flat(output)
            || public.is_empty()
            || public.len() > 64
            || public
                .iter()
                .any(|(name, hash)| !flat(name) || !router_adapter_api::is_digest(hash))
            || limits.max_calls == 0
            || limits.max_calls > 8
            || !(1..=32768).contains(&limits.max_file_bytes)
            || !(1..=8192).contains(&limits.max_output_bytes)
            || !(1..=32768).contains(&limits.max_total_output_bytes)
            || !(1..=20000).contains(&limits.max_exec_ms)
            || !(1..=60000).contains(&limits.max_total_exec_ms)
            || !(1..=90000).contains(&limits.max_session_ms)
            || !(1..=64).contains(&limits.max_scratch_entries)
            || !(1..=16777216).contains(&limits.max_scratch_bytes)
            || preimage
                .as_ref()
                .is_some_and(|hash| public.get(output) != Some(hash))
            || preimage.is_none() && public.contains_key(output)
        {
            return Err("policy.initial_contract");
        }
        let root = directory(root)?;
        let scratch = directory(scratch)?;
        if root.identity == scratch.identity {
            return Err("policy.scratch_root");
        }
        for entry in
            rustix::fs::Dir::read_from(&scratch.file).map_err(|_| "policy.scratch_inventory")?
        {
            let entry = entry.map_err(|_| "policy.scratch_inventory")?;
            let name = entry.file_name().to_bytes();
            if name != b"." && name != b".." {
                return Err("policy.scratch_not_empty");
            }
        }
        let mut output_file = None;
        let target = if let Some(expected) = preimage {
            let mut file = file_at(&root.file, output, false)?;
            let pin = snapshot(&mut file, limits.max_file_bytes as u64)?;
            if pin.hash != expected {
                return Err("policy.preimage");
            }
            output_file = Some(file);
            Some(pin)
        } else {
            absent(&root.file, output)?;
            None
        };
        let mut immutable = BTreeMap::new();
        let mut pinned = Vec::new();
        for (name, expected) in &public {
            if name == output {
                continue;
            }
            let mut file = file_at(&root.file, name, false)?;
            let pin = snapshot(&mut file, limits.max_file_bytes as u64)?;
            if pin.hash != *expected {
                return Err("policy.initial_preimage");
            }
            immutable.insert(name.clone(), pin);
            pinned.push(file);
        }
        let engine = Self {
            root,
            scratch,
            public,
            immutable,
            _pinned_public: pinned,
            _pinned_output: output_file,
            output: output.into(),
            target,
            scratch_state: Scratch::default(),
            limits,
            calls: 0,
            total_output: 0,
            exec_ms: 0,
            started: Instant::now(),
            halted: false,
            journal: vec![],
        };
        engine.verify()?;
        Ok(engine)
    }
    fn verify(&self) -> Result<(), &'static str> {
        self.root.verify()?;
        self.scratch.verify()?;
        for (name, expected) in &self.immutable {
            if snapshot(
                &mut file_at(&self.root.file, name, false)?,
                self.limits.max_file_bytes as u64,
            )? != *expected
            {
                return Err("policy.immutable_changed");
            }
        }
        if let Some(pin) = &self.target {
            if snapshot(
                &mut file_at(&self.root.file, &self.output, false)?,
                self.limits.max_file_bytes as u64,
            )? != *pin
            {
                return Err("policy.target_changed");
            }
        } else {
            absent(&self.root.file, &self.output)?;
        }
        if scan_scratch(&self.scratch, &self.limits)? != self.scratch_state {
            return Err("policy.scratch_changed");
        }
        Ok(())
    }
    fn elapsed(&self) -> u64 {
        self.started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }
    fn location(&self, name: &str) -> Result<(&Directory, String, bool), &'static str> {
        if let Some(flat_name) = name.strip_prefix(".scratch/") {
            if flat(flat_name) {
                return Ok((&self.scratch, flat_name.into(), true));
            }
        } else if flat(name) && (self.public.contains_key(name) || name == self.output) {
            return Ok((&self.root, name.into(), false));
        }
        Err("policy.scope")
    }
    fn read(&mut self, args: &Value) -> Result<ToolResult, &'static str> {
        key_args(args, &["path"], &[])?;
        let name = args["path"].as_str().ok_or("policy.arguments")?;
        let (dir, relative, _) = self.location(name)?;
        let mut file = file_at(&dir.file, &relative, false)?;
        snapshot(&mut file, self.limits.max_file_bytes as u64)?;
        file.seek(SeekFrom::Start(0)).map_err(|_| "policy.seek")?;
        let mut text = String::new();
        if file
            .take(self.limits.max_file_bytes as u64 + 1)
            .read_to_string(&mut text)
            .is_err()
        {
            self.halted = true;
            return Err("policy.read_utf8");
        }
        Ok(ToolResult {
            stdout: text,
            stderr: String::new(),
            exit_code: 0,
            termination: "exited".into(),
            truncated: false,
            elapsed_ms: 0,
        })
    }
    fn write(&mut self, args: &Value) -> Result<ToolResult, &'static str> {
        key_args(args, &["path", "content"], &["create_new"])?;
        let name = args["path"].as_str().ok_or("policy.arguments")?;
        let raw = args["content"]
            .as_str()
            .ok_or("policy.arguments")?
            .as_bytes();
        let create = args
            .get("create_new")
            .map(Value::as_bool)
            .unwrap_or(Some(false))
            .ok_or("policy.arguments")?;
        if raw.len() > self.limits.max_file_bytes {
            self.halted = true;
            return Err("policy.file_budget");
        }
        let (dir, relative, scratch) = self.location(name)?;
        if !scratch && relative != self.output {
            return Err("policy.scope");
        }
        let previous = if scratch {
            self.scratch_state.files.get(&relative)
        } else {
            self.target.as_ref()
        }
        .cloned();
        if create && previous.is_some() || !create && previous.is_none() {
            return Err("policy.creation_mode");
        }
        if scratch
            && (self.scratch_state.entries + usize::from(create) > self.limits.max_scratch_entries
                || self.scratch_state.bytes - previous.as_ref().map_or(0, |p| p.bytes)
                    + raw.len() as u64
                    > self.limits.max_scratch_bytes)
        {
            self.halted = true;
            return Err("policy.scratch_budget");
        }
        let mut file = if create {
            absent(&dir.file, &relative)?;
            File::from(
                openat(
                    &dir.file,
                    relative.as_str(),
                    OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::RDWR
                        | OFlags::NOFOLLOW
                        | OFlags::NONBLOCK
                        | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                )
                .map_err(|_| "policy.create")?,
            )
        } else {
            let mut file = file_at(&dir.file, &relative, true)?;
            if Some(snapshot(
                &mut file,
                if scratch {
                    self.limits.max_scratch_bytes
                } else {
                    self.limits.max_file_bytes as u64
                },
            )?) != previous
            {
                return Err("policy.preimage");
            }
            file
        };
        if file
            .seek(SeekFrom::Start(0))
            .and_then(|_| file.write_all(raw))
            .and_then(|()| file.set_len(raw.len() as u64))
            .and_then(|()| file.sync_all())
            .is_err()
        {
            self.halted = true;
            return Err("policy.write");
        }
        let pin = snapshot(&mut file, self.limits.max_file_bytes as u64)?;
        if pin.hash != content_digest(raw) {
            self.halted = true;
            return Err("policy.written_hash");
        }
        if scratch {
            self.scratch_state = scan_scratch(&self.scratch, &self.limits)?;
        } else {
            self.target = Some(pin);
            self._pinned_output = Some(file);
        }
        Ok(ToolResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
            termination: "exited".into(),
            truncated: false,
            elapsed_ms: 0,
        })
    }
    fn execute(
        &mut self,
        args: &Value,
        exec: &mut impl FnMut(&[String], u64, usize) -> Result<ToolResult, &'static str>,
    ) -> Result<ToolResult, &'static str> {
        key_args(args, &["argv"], &["timeout_ms"])?;
        let values = args["argv"].as_array().ok_or("policy.arguments")?;
        if values.is_empty() || values.len() > 32 {
            return Err("policy.argv");
        }
        let argv = values
            .iter()
            .map(|v| {
                v.as_str()
                    .filter(|s| !s.contains('\0') && s.len() <= 4096)
                    .map(str::to_owned)
                    .ok_or("policy.argv")
            })
            .collect::<Result<Vec<_>, _>>()?;
        if argv.iter().map(String::len).sum::<usize>() > 16384
            || !matches!(argv[0].as_str(), "python3" | "rustc")
                && !argv[0].strip_prefix(".scratch/").is_some_and(flat)
        {
            return Err("policy.program");
        }
        let requested = match args.get("timeout_ms") {
            Some(v) => v.as_u64().filter(|n| *n > 0).ok_or("policy.timeout")?,
            None => self.limits.max_exec_ms,
        };
        if requested > self.limits.max_exec_ms {
            self.halted = true;
            return Err("policy.time_budget");
        }
        let timeout = requested
            .min(self.limits.max_total_exec_ms.saturating_sub(self.exec_ms))
            .min(self.limits.max_session_ms.saturating_sub(self.elapsed()));
        if timeout == 0 {
            self.halted = true;
            return Err("policy.time_budget");
        }
        let started = Instant::now();
        let invoked = exec(
            &argv,
            timeout,
            self.limits
                .max_output_bytes
                .min(self.limits.max_total_output_bytes - self.total_output),
        );
        let wall: u64 = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        let mut result = match invoked {
            Ok(result) => result,
            Err(_) => {
                self.halted = true;
                self.exec_ms = self
                    .exec_ms
                    .checked_add(wall)
                    .ok_or("policy.time_overflow")?;
                return Err("policy.exec");
            }
        };
        result.elapsed_ms = result.elapsed_ms.max(wall);
        self.exec_ms = match self.exec_ms.checked_add(result.elapsed_ms) {
            Some(value) => value,
            None => {
                self.halted = true;
                return Err("policy.time_overflow");
            }
        };
        if result.elapsed_ms > timeout
            || self.exec_ms >= self.limits.max_total_exec_ms
            || self.elapsed() >= self.limits.max_session_ms
        {
            result.termination = "time_budget_exhausted".into();
            self.halted = true;
        }
        if result.termination != "exited" || result.truncated {
            self.halted = true;
        }
        self.scratch_state = match scan_scratch(&self.scratch, &self.limits) {
            Ok(state) => state,
            Err(error) => {
                self.halted = true;
                return Err(error);
            }
        };
        Ok(result)
    }
    pub fn dispatch(
        &mut self,
        name: &str,
        args: &Value,
        exec: &mut impl FnMut(&[String], u64, usize) -> Result<ToolResult, &'static str>,
    ) -> Result<Value, &'static str> {
        if self.halted {
            return Err("policy.halted");
        }
        let digest = match argument_digest(args) {
            Ok(digest) => Some(digest),
            Err(error) => {
                self.halted = true;
                let mut record = self.record(name, None);
                record.status = "input_bound".into();
                self.append(record);
                return Err(error);
            }
        };
        let mut record = self.record(name, digest);
        if self.calls >= self.limits.max_calls
            || self.elapsed() >= self.limits.max_session_ms
            || self.total_output >= self.limits.max_total_output_bytes
        {
            self.halted = true;
            record.status = "budget_exhausted".into();
            self.append(record);
            return Err("policy.budget");
        }
        self.calls += 1;
        let started = Instant::now();
        if let Err(error) = self.verify() {
            self.halted = true;
            record.status = "precondition_failed".into();
            self.append(record);
            return Err(error);
        }
        let invoked = match name {
            "read_file" => self.read(args),
            "write_file" => self.write(args),
            "exec" => self.execute(args, exec),
            _ => Err("policy.tool"),
        };
        if let Err(error) = self.verify() {
            self.halted = true;
            record.status = "postcondition_failed".into();
            record.elapsed_ms = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
            self.append(record);
            return Err(error);
        }
        let mut result = match invoked {
            Ok(result) => result,
            Err(error) => {
                record.elapsed_ms = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                self.append(record);
                return Err(error);
            }
        };
        result.elapsed_ms = result
            .elapsed_ms
            .max(started.elapsed().as_millis().try_into().unwrap_or(u64::MAX));
        if self.elapsed() >= self.limits.max_session_ms {
            result.termination = "time_budget_exhausted".into();
            self.halted = true;
        }
        let cap = self
            .limits
            .max_output_bytes
            .min(self.limits.max_total_output_bytes - self.total_output);
        if result.stdout.len() + result.stderr.len() > cap {
            fn trim(text: &mut String, bound: usize) {
                let mut end = bound.min(text.len());
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                text.truncate(end);
            }
            trim(&mut result.stdout, cap);
            trim(&mut result.stderr, cap - result.stdout.len());
            result.truncated = true;
            self.halted = true;
        }
        self.total_output += result.stdout.len() + result.stderr.len();
        if self.total_output >= self.limits.max_total_output_bytes {
            self.halted = true;
        }
        record.status = "returned".into();
        record.output_bytes = result.stdout.len() + result.stderr.len();
        record.exit_code = Some(result.exit_code);
        record.elapsed_ms = result.elapsed_ms;
        record.truncated = result.truncated;
        if name == "write_file" {
            record.file_sha256 = args
                .get("content")
                .and_then(Value::as_str)
                .map(|s| content_digest(s.as_bytes()));
        }
        self.append(record);
        serde_json::to_value(result).map_err(|_| "policy.result")
    }
    pub fn preparation_binding(&self) -> Result<String, &'static str> {
        self.verify()?;
        let bytes = serde_json::to_vec(&(
            "finite-file-policy-preparation-v1",
            self.root.identity,
            self.scratch.identity,
            &self.public,
            &self.immutable,
            &self.target,
            &self.limits,
        ))
        .map_err(|_| "policy.binding")?;
        if bytes.len() > 32768 {
            return Err("policy.binding_bound");
        }
        Ok(content_digest(&bytes))
    }
    pub fn verify_terminal_output(&self, output: &super::ToolOutput) -> Result<(), &'static str> {
        if output.relative != self.output {
            return Err("policy.terminal_scope");
        }
        self.root.verify()?;
        self.scratch.verify()?;
        for (name, expected) in &self.immutable {
            if snapshot(
                &mut file_at(&self.root.file, name, false)?,
                self.limits.max_file_bytes as u64,
            )? != *expected
            {
                return Err("policy.terminal_public_changed");
            }
        }
        let current = snapshot(
            &mut file_at(&self.root.file, &self.output, false)?,
            self.limits.max_file_bytes as u64,
        )?;
        if self.target.as_ref().is_some_and(|initial| {
            (initial.dev, initial.ino, initial.mode) != (current.dev, current.ino, current.mode)
        }) || (
            current.dev,
            current.ino,
            current.mode,
            current.bytes,
            current.hash.as_str(),
        ) != (
            output.device,
            output.inode,
            output.mode,
            output.bytes,
            output.sha256.as_str(),
        ) {
            return Err("policy.terminal_output_changed");
        }
        self.root.verify()
    }
    pub fn terminal_output(&self) -> Result<Option<super::ToolOutput>, &'static str> {
        self.verify()?;
        Ok(self.target.as_ref().map(|pin| super::ToolOutput {
            relative: self.output.clone(),
            sha256: pin.hash.clone(),
            device: pin.dev,
            inode: pin.ino,
            mode: pin.mode,
            bytes: pin.bytes,
        }))
    }
    pub fn journal(&self) -> &[JournalEntry] {
        &self.journal
    }
    pub fn halted(&self) -> bool {
        self.halted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_adapter_api::content_digest;
    use serde_json::json;
    use std::{fs, os::unix::fs::symlink};

    fn limits() -> Limits {
        Limits {
            max_calls: 8,
            max_file_bytes: 32768,
            max_output_bytes: 8192,
            max_total_output_bytes: 32768,
            max_exec_ms: 20000,
            max_total_exec_ms: 60000,
            max_session_ms: 90000,
            max_scratch_entries: 64,
            max_scratch_bytes: 16777216,
        }
    }
    fn fixture(create: bool) -> (tempfile::TempDir, Engine) {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("scratch")).unwrap();
        fs::write(root.path().join("statement.md"), b"public statement").unwrap();
        let mut public =
            BTreeMap::from([("statement.md".into(), content_digest(b"public statement"))]);
        let preimage = if create {
            None
        } else {
            fs::write(root.path().join("lib.rs"), b"initial").unwrap();
            public.insert("lib.rs".into(), content_digest(b"initial"));
            Some(content_digest(b"initial"))
        };
        let output = if create { "review.json" } else { "lib.rs" };
        let engine = Engine::open(
            root.path(),
            &root.path().join("scratch"),
            public,
            output,
            preimage,
            limits(),
        )
        .unwrap();
        (root, engine)
    }
    fn no_exec(_: &[String], _: u64, _: usize) -> Result<ToolResult, &'static str> {
        panic!("file call executed a process")
    }
    fn result(code: i32, text: &str) -> ToolResult {
        ToolResult {
            stdout: text.into(),
            stderr: String::new(),
            exit_code: code,
            termination: "exited".into(),
            truncated: false,
            elapsed_ms: 1,
        }
    }

    #[test]
    fn writes_only_the_approved_existing_inode_and_reads_public_bytes() {
        let (root, mut engine) = fixture(false);
        let read = engine
            .dispatch("read_file", &json!({"path":"statement.md"}), &mut no_exec)
            .unwrap();
        assert_eq!(read["stdout"], "public statement");
        assert!(
            engine
                .dispatch(
                    "write_file",
                    &json!({"path":"statement.md","content":"bad"}),
                    &mut no_exec
                )
                .is_err()
        );
        engine
            .dispatch(
                "write_file",
                &json!({"path":"lib.rs","content":"updated"}),
                &mut no_exec,
            )
            .unwrap();
        assert_eq!(fs::read(root.path().join("lib.rs")).unwrap(), b"updated");
        assert_eq!(
            fs::read(root.path().join("statement.md")).unwrap(),
            b"public statement"
        );
        let journal = serde_json::to_string(&engine.journal()).unwrap();
        assert!(!journal.contains("updated") && !journal.contains("public statement"));
    }

    #[test]
    fn absent_output_requires_explicit_creation_and_refuses_duplicate_creation() {
        let (root, mut engine) = fixture(true);
        assert!(!root.path().join("review.json").exists());
        assert!(
            engine
                .dispatch(
                    "write_file",
                    &json!({"path":"review.json","content":"first"}),
                    &mut no_exec
                )
                .is_err()
        );
        engine
            .dispatch(
                "write_file",
                &json!({"path":"review.json","content":"first","create_new":true}),
                &mut no_exec,
            )
            .unwrap();
        assert!(
            engine
                .dispatch(
                    "write_file",
                    &json!({"path":"review.json","content":"wrong","create_new":true}),
                    &mut no_exec
                )
                .is_err()
        );
        assert_eq!(fs::read(root.path().join("review.json")).unwrap(), b"first");
        engine
            .dispatch(
                "write_file",
                &json!({"path":"review.json","content":"corrected","create_new":false}),
                &mut no_exec,
            )
            .unwrap();
        assert_eq!(
            fs::read(root.path().join("review.json")).unwrap(),
            b"corrected"
        );
    }

    #[test]
    fn refuses_traversal_symlinks_hardlinks_and_changed_preimages() {
        for kind in ["traversal", "symlink", "hardlink", "changed"] {
            let (root, mut engine) = fixture(false);
            let outside = root.path().join("outside");
            fs::write(&outside, b"canary").unwrap();
            let name = if kind == "traversal" {
                "../outside"
            } else {
                "lib.rs"
            };
            match kind {
                "symlink" => {
                    fs::remove_file(root.path().join("lib.rs")).unwrap();
                    symlink(&outside, root.path().join("lib.rs")).unwrap();
                }
                "hardlink" => {
                    fs::hard_link(root.path().join("lib.rs"), root.path().join("linked")).unwrap();
                }
                "changed" => fs::write(root.path().join("lib.rs"), b"tampered").unwrap(),
                _ => {}
            }
            assert!(
                engine
                    .dispatch(
                        "write_file",
                        &json!({"path":name,"content":"bad"}),
                        &mut no_exec
                    )
                    .is_err(),
                "{kind}"
            );
            assert_eq!(fs::read(outside).unwrap(), b"canary");
        }
    }

    #[test]
    fn ninth_call_and_truncated_output_make_refusal_sticky_before_further_writes() {
        let (root, mut engine) = fixture(false);
        for _ in 0..8 {
            engine
                .dispatch("read_file", &json!({"path":"statement.md"}), &mut no_exec)
                .unwrap();
        }
        assert!(
            engine
                .dispatch(
                    "write_file",
                    &json!({"path":"lib.rs","content":"bad"}),
                    &mut no_exec
                )
                .is_err()
        );
        assert!(engine.halted());
        assert_eq!(fs::read(root.path().join("lib.rs")).unwrap(), b"initial");
        let (_root, mut engine) = fixture(false);
        let mut execute = |_: &[String], _: u64, _: usize| {
            let mut r = result(0, "partial");
            r.truncated = true;
            Ok(r)
        };
        let r = engine
            .dispatch(
                "exec",
                &json!({"argv":["python3","-B","feedback.py"]}),
                &mut execute,
            )
            .unwrap();
        assert_eq!(r["truncated"], true);
        assert!(engine.halted());
        assert!(
            engine
                .dispatch("read_file", &json!({"path":"statement.md"}), &mut no_exec)
                .is_err()
        );
    }

    #[test]
    fn exec_returns_red_feedback_and_revalidates_public_inputs_after_callback() {
        let (root, mut engine) = fixture(false);
        let mut execute = |argv: &[String], timeout: u64, max: usize| {
            assert_eq!(argv, ["python3", "-B", "feedback.py"]);
            assert!(timeout <= 20000);
            assert_eq!(max, 8192);
            Ok(result(1, "real red diagnostic"))
        };
        let value = engine
            .dispatch(
                "exec",
                &json!({"argv":["python3","-B","feedback.py"]}),
                &mut execute,
            )
            .unwrap();
        assert_eq!(value["exit_code"], 1);
        assert_eq!(value["stdout"], "real red diagnostic");
        assert!(!engine.halted());
        let mut corrupt = |_: &[String], _: u64, _: usize| {
            fs::write(root.path().join("statement.md"), b"bad").unwrap();
            Ok(result(0, "green"))
        };
        assert!(
            engine
                .dispatch(
                    "exec",
                    &json!({"argv":["python3","-c","pass"]}),
                    &mut corrupt
                )
                .is_err()
        );
        assert!(engine.halted());
    }

    #[test]
    fn scratch_writes_persist_and_exec_created_files_are_scoped() {
        let (root, mut engine) = fixture(false);
        engine
            .dispatch(
                "write_file",
                &json!({"path":".scratch/check.rs","content":"public check","create_new":true}),
                &mut no_exec,
            )
            .unwrap();
        let mut execute = |_: &[String], _: u64, _: usize| {
            assert_eq!(
                fs::read(root.path().join("scratch/check.rs")).unwrap(),
                b"public check"
            );
            fs::write(root.path().join("scratch/check-bin"), b"owned binary").unwrap();
            Ok(result(0, "compiled"))
        };
        engine
            .dispatch(
                "exec",
                &json!({"argv":["rustc",".scratch/check.rs"]}),
                &mut execute,
            )
            .unwrap();
        let value = engine
            .dispatch(
                "read_file",
                &json!({"path":".scratch/check-bin"}),
                &mut no_exec,
            )
            .unwrap();
        assert_eq!(value["stdout"], "owned binary");
    }

    #[test]
    fn replacing_an_immutable_inode_with_identical_bytes_is_still_refused() {
        let (root, mut engine) = fixture(false);
        let mut substitute = |_: &[String], _: u64, _: usize| {
            fs::rename(
                root.path().join("statement.md"),
                root.path().join("retained-original"),
            )
            .unwrap();
            fs::write(root.path().join("statement.md"), b"public statement").unwrap();
            Ok(result(0, "unchanged bytes"))
        };
        assert!(
            engine
                .dispatch(
                    "exec",
                    &json!({"argv":["python3","-c","pass"]}),
                    &mut substitute
                )
                .is_err(),
            "an immutable file's identity changed despite equal content"
        );
        assert!(engine.halted());
    }

    #[test]
    fn file_output_time_and_scratch_exhaustion_are_sticky() {
        let (root, mut engine) = fixture(false);
        assert!(
            engine
                .dispatch(
                    "write_file",
                    &json!({"path":"lib.rs","content":"x".repeat(32769)}),
                    &mut no_exec
                )
                .is_err()
        );
        assert!(engine.halted());
        assert_eq!(fs::read(root.path().join("lib.rs")).unwrap(), b"initial");

        let (_root, mut engine) = fixture(false);
        let mut noisy = |_: &[String], _: u64, _: usize| Ok(result(0, &"é".repeat(4097)));
        let value = engine
            .dispatch("exec", &json!({"argv":["python3","-c","pass"]}), &mut noisy)
            .unwrap();
        assert_eq!(value["stdout"].as_str().unwrap().len(), 8192);
        assert_eq!(value["truncated"], true);
        assert!(engine.halted());

        let (_root, mut engine) = fixture(false);
        let mut overtime = |_: &[String], _: u64, _: usize| {
            let mut value = result(0, "late");
            value.elapsed_ms = 20001;
            Ok(value)
        };
        let value = engine
            .dispatch(
                "exec",
                &json!({"argv":["python3","-c","pass"]}),
                &mut overtime,
            )
            .unwrap();
        assert_eq!(value["termination"], "time_budget_exhausted");
        assert!(engine.halted());

        let (root, mut engine) = fixture(false);
        engine.limits.max_scratch_entries = 1;
        let mut overflow = |_: &[String], _: u64, _: usize| {
            fs::write(root.path().join("scratch/one"), b"a").unwrap();
            fs::write(root.path().join("scratch/two"), b"b").unwrap();
            Ok(result(0, "overflow"))
        };
        assert!(
            engine
                .dispatch(
                    "exec",
                    &json!({"argv":["python3","-c","pass"]}),
                    &mut overflow
                )
                .is_err()
        );
        assert!(engine.halted());
    }

    #[test]
    fn real_wall_clock_overrides_a_zero_callback_duration() {
        let (_root, mut engine) = fixture(false);
        engine.limits.max_exec_ms = 1;
        let mut delayed = |_: &[String], timeout: u64, _: usize| {
            assert_eq!(timeout, 1);
            std::thread::sleep(std::time::Duration::from_millis(20));
            let mut r = result(0, "late");
            r.elapsed_ms = 0;
            Ok(r)
        };
        let value = engine
            .dispatch(
                "exec",
                &json!({"argv":["python3","-c","pass"]}),
                &mut delayed,
            )
            .unwrap();
        assert_eq!(value["termination"], "time_budget_exhausted");
        assert!(value["elapsed_ms"].as_u64().unwrap() >= 20);
        assert!(engine.halted());
    }

    #[test]
    fn oversized_arguments_and_permission_changes_are_logged_without_content() {
        use std::os::unix::fs::PermissionsExt;
        let (root, mut engine) = fixture(false);
        let value = json!({"path":"lib.rs","content":"bad","extra":"CANARY".repeat(12000)});
        assert!(engine.dispatch("write_file", &value, &mut no_exec).is_err());
        assert!(engine.halted());
        assert_eq!(fs::read(root.path().join("lib.rs")).unwrap(), b"initial");
        assert_eq!(engine.journal().len(), 1);
        assert!(engine.journal()[0].argument_sha256.is_none());
        assert!(
            !serde_json::to_string(engine.journal())
                .unwrap()
                .contains("CANARY")
        );
        let (root, mut engine) = fixture(false);
        fs::set_permissions(
            root.path().join("statement.md"),
            fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert!(
            engine
                .dispatch("read_file", &json!({"path":"statement.md"}), &mut no_exec)
                .is_err()
        );
        assert!(engine.halted());
        assert_eq!(engine.journal()[0].status, "precondition_failed");
        let (root, mut engine) = fixture(false);
        let mut chmod = |_: &[String], _: u64, _: usize| {
            fs::set_permissions(
                root.path().join("statement.md"),
                fs::Permissions::from_mode(0o444),
            )
            .unwrap();
            Ok(result(0, "same bytes"))
        };
        assert!(
            engine
                .dispatch("exec", &json!({"argv":["python3","-c","pass"]}), &mut chmod)
                .is_err()
        );
        assert!(engine.halted());
        assert_eq!(engine.journal()[0].status, "postcondition_failed");
    }

    #[test]
    fn cumulative_output_exec_session_and_scratch_byte_limits_stop_later_effects() {
        let (_root, mut engine) = fixture(false);
        engine.limits.max_total_output_bytes = 5;
        let mut emit = |_: &[String], _: u64, _: usize| Ok(result(0, "abc"));
        engine
            .dispatch("exec", &json!({"argv":["python3","-c","pass"]}), &mut emit)
            .unwrap();
        let r = engine
            .dispatch("exec", &json!({"argv":["python3","-c","pass"]}), &mut emit)
            .unwrap();
        assert_eq!(r["stdout"], "ab");
        assert_eq!(r["truncated"], true);
        assert!(engine.halted());

        let (_root, mut engine) = fixture(false);
        engine.limits.max_total_exec_ms = 20000;
        let mut elapsed = |_: &[String], _: u64, _: usize| {
            let mut value = result(0, "");
            value.elapsed_ms = 10000;
            Ok(value)
        };
        engine
            .dispatch(
                "exec",
                &json!({"argv":["python3","-c","pass"]}),
                &mut elapsed,
            )
            .unwrap();
        let r = engine
            .dispatch(
                "exec",
                &json!({"argv":["python3","-c","pass"]}),
                &mut elapsed,
            )
            .unwrap();
        assert_eq!(r["termination"], "time_budget_exhausted");
        assert!(engine.halted());

        let (root, mut engine) = fixture(false);
        engine.started = Instant::now()
            .checked_sub(std::time::Duration::from_millis(90001))
            .unwrap();
        assert!(
            engine
                .dispatch(
                    "write_file",
                    &json!({"path":"lib.rs","content":"bad"}),
                    &mut no_exec
                )
                .is_err()
        );
        assert!(engine.halted());
        assert_eq!(fs::read(root.path().join("lib.rs")).unwrap(), b"initial");

        let (root, mut engine) = fixture(false);
        engine.limits.max_scratch_bytes = 4;
        assert!(
            engine
                .dispatch(
                    "write_file",
                    &json!({"path":".scratch/large","content":"12345","create_new":true}),
                    &mut no_exec
                )
                .is_err()
        );
        assert!(engine.halted());
        assert!(!root.path().join("scratch/large").exists());
    }
}
