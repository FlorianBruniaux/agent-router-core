use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Packet {
    pub assignment_id: String,
    pub model: String,
    pub effort: String,
    pub condition: String,
    pub acceptance_sha256: String,
    pub packet_sha256: String,
    pub output: String,
    pub create_new: bool,
    pub files: BTreeMap<String, String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Packets {
    pub preparation_seal_sha256: String,
    pub corpus_seal_sha256: String,
    pub assignments: Vec<Packet>,
}
pub fn packets() -> Result<Packets, &'static str> {
    let raw = include_bytes!("packets.json");
    if router_adapter_api::content_digest(raw)
        != "2d4d225e528fff5ba402e7265140521f212d7b4a3443c3dd62f1db00f9e0281a"
    {
        return Err("packet source changed");
    }
    let p: Packets = serde_json::from_slice(raw).map_err(|_| "packet schema")?;
    if p.preparation_seal_sha256
        != "7fd4cae9f7951a07fe8c822bf87a01bf24a52989f8c0198f51bbb8cd4e102dfa"
        || p.corpus_seal_sha256
            != "a21c0d8fb839a9f1e5c731c34825fa1df61fcd3434d39ccc93713e870c715a58"
        || p.assignments.len() != 24
    {
        return Err("packet seal");
    }
    Ok(p)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sealed_matrix_preserves_all_pairs_and_output_modes() {
        let packets = packets().unwrap();
        assert_eq!(packets.assignments.len(), 24);
        let mut seen = std::collections::BTreeSet::new();
        for p in &packets.assignments {
            assert!(seen.insert(p.assignment_id.clone()));
            let pieces: Vec<_> = p.assignment_id.split('-').collect();
            assert_eq!(
                p.model,
                if pieces[1].starts_with('L') {
                    "gpt-6-luna"
                } else {
                    "gpt-6-astra"
                }
            );
            assert_eq!(
                p.effort,
                if pieces[1].ends_with('m') {
                    "medium"
                } else {
                    "xhigh"
                }
            );
            assert_eq!(p.files.contains_key("HARNESS.md"), p.condition == "H1");
            assert_eq!(p.files.contains_key("feedback.py"), p.condition == "H1");
            assert_eq!(p.create_new, pieces[0] == "t05");
            assert_eq!(p.files.contains_key(&p.output), !p.create_new);
            let other = packets
                .assignments
                .iter()
                .find(|v| {
                    v.assignment_id[..v.assignment_id.len() - 1]
                        == p.assignment_id[..p.assignment_id.len() - 1]
                        && v.condition != p.condition
                })
                .unwrap();
            assert_eq!(other.acceptance_sha256, p.acceptance_sha256);
            assert_eq!(other.files["statement.md"], p.files["statement.md"]);
        }
    }
}
