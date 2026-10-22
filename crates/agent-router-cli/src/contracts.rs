//! The output contracts a caller can validate: one table shared by
//! `schema` and `version --json`, so the two can never disagree.
use serde::Serialize;

/// A contract `schema_version` as its output carries it: the decision envelope
/// uses a string, every other output a number.
#[derive(Clone, Copy, Serialize)]
#[serde(untagged)]
pub(crate) enum SchemaVersion {
    Number(u64),
    Text(&'static str),
}

pub(crate) struct Contract {
    pub name: &'static str,
    /// The command line that prints this output.
    pub command: &'static str,
    /// `schema_version` values this binary reads or writes for the output.
    pub versions: &'static [SchemaVersion],
    /// The JSON Schema document, embedded at compile time.
    pub schema: &'static str,
}

pub(crate) const CONTRACTS: [Contract; 6] = [
    Contract {
        name: "error",
        command: "any command with --json, on failure (stderr)",
        versions: &[SchemaVersion::Number(1)],
        schema: include_str!("schemas/error.schema.json"),
    },
    Contract {
        name: "feedback-report",
        command: "feedback report",
        versions: &[
            SchemaVersion::Number(1),
            SchemaVersion::Number(2),
            SchemaVersion::Number(3),
            SchemaVersion::Number(4),
            SchemaVersion::Number(5),
        ],
        schema: include_str!("schemas/feedback-report.schema.json"),
    },
    Contract {
        name: "feedback-summary",
        command: "feedback summary",
        versions: &[
            SchemaVersion::Number(1),
            SchemaVersion::Number(2),
            SchemaVersion::Number(3),
            SchemaVersion::Number(4),
        ],
        schema: include_str!("schemas/feedback-summary.schema.json"),
    },
    Contract {
        name: "route-decision",
        command: "route --json",
        versions: &[SchemaVersion::Text("1")],
        schema: include_str!("schemas/route-decision.schema.json"),
    },
    Contract {
        name: "run-observation",
        command: "observe --json",
        versions: &[
            SchemaVersion::Number(1),
            SchemaVersion::Number(2),
            SchemaVersion::Number(3),
        ],
        schema: include_str!("schemas/run-observation.schema.json"),
    },
    Contract {
        name: "version",
        command: "version --json",
        versions: &[SchemaVersion::Number(1)],
        schema: include_str!("schemas/version.schema.json"),
    },
];

pub(crate) fn find(name: &str) -> Option<&'static Contract> {
    CONTRACTS.iter().find(|contract| contract.name == name)
}
