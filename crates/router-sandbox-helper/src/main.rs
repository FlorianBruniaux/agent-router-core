#![forbid(unsafe_code)]
//! Dedicated child: resource limits never modify the router parent.
mod watchdog;
use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
use std::{
    ffi::{OsStr, OsString},
    os::unix::process::CommandExt,
    process::Command,
};

fn main() {
    if let Err(code) = run() {
        eprintln!("sandbox-helper.{code}");
        std::process::exit(125);
    }
}
fn run() -> Result<(), &'static str> {
    let all_args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let mut args = all_args.clone().into_iter();
    let mut values = Vec::new();
    for (index, name) in [
        "--cpu-seconds",
        "--address-space-bytes",
        "--max-open-files",
        "--max-processes",
        "--max-file-bytes",
    ]
    .into_iter()
    .enumerate()
    {
        if args.next().as_deref() != Some(OsStr::new(name)) {
            return Err("arguments");
        }
        let value = args
            .next()
            .and_then(|v| v.into_string().ok())
            .ok_or("arguments")?;
        let value = if index == 1 && value == "none" {
            None
        } else {
            Some(value.parse::<u64>().map_err(|_| "arguments")?)
        };
        values.push(value);
    }
    for (index, (min, max)) in [
        (1, 86_400),
        (64 * 1024 * 1024, 1024 * 1024 * 1024 * 1024),
        (16, 4096),
        (1, 4096),
        (1024, 1024 * 1024 * 1024),
    ]
    .into_iter()
    .enumerate()
    {
        if values[index].is_some_and(|v| !(min..=max).contains(&v)) {
            return Err("bounds");
        }
    }
    let next = args.next().ok_or("arguments")?;
    if next == "--supervise-v1" {
        let code = watchdog::supervise(all_args[..10].to_vec(), args.collect())?;
        std::process::exit(code);
    }
    let resources = [
        Resource::Cpu,
        Resource::As,
        Resource::Nofile,
        Resource::Nproc,
        Resource::Fsize,
    ];
    for (resource, value) in resources.into_iter().zip(&values) {
        if let Some(value) = value {
            let hard = getrlimit(resource).maximum.unwrap_or(u64::MAX);
            let value = (*value).min(hard);
            setrlimit(
                resource,
                Rlimit {
                    current: Some(value),
                    maximum: Some(value),
                },
            )
            .map_err(|_| match resource {
                Resource::Cpu => "setrlimit.cpu",
                Resource::As => "setrlimit.address_space",
                Resource::Nofile => "setrlimit.open_files",
                Resource::Nproc => "setrlimit.processes",
                Resource::Fsize => "setrlimit.file_size",
                _ => "setrlimit",
            })?;
        }
    }
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|_| "core_limit")?;
    if next == "--probe" {
        if args.next().is_some() {
            return Err("arguments");
        }
        for (resource, requested) in resources.into_iter().zip(&values) {
            if let Some(requested) = requested {
                let limit = getrlimit(resource);
                if limit.current.unwrap_or(u64::MAX) > *requested
                    || limit.maximum.unwrap_or(u64::MAX) > *requested
                {
                    return Err("limits_not_applied");
                }
            }
        }
        println!(
            "router-sandbox-helper-v1:limits-applied:address-space={}",
            if values[1].is_some() {
                "enforced"
            } else {
                "not-requested"
            }
        );
        return Ok(());
    }
    if next != "--" {
        return Err("arguments");
    }
    let program = args.next().ok_or("arguments")?;
    if !std::path::Path::new(&program).is_absolute() {
        return Err("absolute_program_required");
    }
    let arguments: Vec<OsString> = args.collect();
    if arguments.len() > 256 {
        return Err("arguments");
    }
    let _error = Command::new(program).args(arguments).exec();
    Err("exec")
}
