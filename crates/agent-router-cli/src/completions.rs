//! `completions <shell>`: a static completion script on stdout, generated from
//! the command definition itself so it cannot drift from `--help`.
use clap::{CommandFactory, ValueEnum};

use crate::{CliError, Outcome, cli::Cli};

#[derive(Clone, Copy, ValueEnum)]
pub enum CompletionShell {
    Bash,
    Zsh,
    Fish,
}

impl From<CompletionShell> for clap_complete::Shell {
    fn from(shell: CompletionShell) -> Self {
        match shell {
            CompletionShell::Bash => Self::Bash,
            CompletionShell::Zsh => Self::Zsh,
            CompletionShell::Fish => Self::Fish,
        }
    }
}

pub(crate) fn run(shell: CompletionShell) -> Result<Outcome, CliError> {
    let mut command = Cli::command();
    let name = command.get_name().to_owned();
    let mut script = Vec::new();
    clap_complete::generate(
        clap_complete::Shell::from(shell),
        &mut command,
        name,
        &mut script,
    );
    Ok(Outcome {
        output: String::from_utf8(script).map_err(|_| CliError::Internal)?,
        exit_code: std::process::ExitCode::SUCCESS,
    })
}
