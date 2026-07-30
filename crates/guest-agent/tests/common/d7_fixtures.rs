use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub const STATE_FIXTURES: [(char, &str); 9] = [
    ('R', "stat/stat-running.txt"),
    ('S', "stat/stat-sleeping.txt"),
    ('D', "stat/stat-disk-sleep.txt"),
    ('Z', "stat/stat-zombie.txt"),
    ('T', "stat/stat-stopped.txt"),
    ('t', "stat/stat-tracing-stop.txt"),
    ('X', "stat/stat-dead.txt"),
    ('P', "stat/stat-parked.txt"),
    ('I', "stat/stat-idle.txt"),
];

#[derive(Debug, Deserialize)]
pub struct D7FixtureManifest {
    pub schema_version: u32,
    pub fixtures: Vec<D7FixtureRecord>,
}

#[derive(Debug, Deserialize)]
pub struct D7FixtureRecord {
    pub path: String,
    pub kind: String,
    pub captured_at: String,
    pub kernel_release: String,
    pub architecture: String,
    pub command: String,
    pub state: Option<String>,
    pub sha256: String,
    pub provenance: D7FixtureProvenance,
}

#[derive(Debug, Deserialize)]
pub struct D7FixtureProvenance {
    pub kind: String,
    pub source: Option<String>,
    pub mutation: Option<String>,
}

pub fn fixture_path(relative: impl AsRef<Path>) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/d7")
        .join(relative)
}

pub fn fixture_bytes(relative: impl AsRef<Path>) -> Vec<u8> {
    let path = fixture_path(relative);
    fs::read(&path).unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

pub fn fixture_text(relative: impl AsRef<Path>) -> String {
    let path = fixture_path(relative);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read UTF-8 fixture {}: {error}", path.display()))
}

pub fn stat_fixture(state: char) -> Vec<u8> {
    let (_, path) = STATE_FIXTURES
        .iter()
        .find(|(known, _)| *known == state)
        .unwrap_or_else(|| panic!("no D7 stat fixture for state {state:?}"));
    fixture_bytes(path)
}

pub fn manifest() -> D7FixtureManifest {
    serde_json::from_slice(&fixture_bytes("manifest.json"))
        .expect("D7 fixture manifest must be valid JSON")
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::process::Command;

    use super::*;

    #[test]
    fn manifest_covers_every_fixture_exactly_once() {
        let root = fixture_path("");
        let manifest = manifest();
        let mut manifest_paths = BTreeSet::new();

        assert_eq!(manifest.schema_version, 1);
        for record in &manifest.fixtures {
            assert!(
                manifest_paths.insert(record.path.clone()),
                "duplicate manifest path: {}",
                record.path
            );
            assert!(!record.captured_at.is_empty());
            assert!(!record.kernel_release.is_empty());
            assert!(!record.architecture.is_empty());
            assert!(!record.command.is_empty());
        }

        assert_eq!(manifest_paths, fixture_files(&root));
        assert!(fixture_text("status/cat.txt").contains("Name:"));
    }

    #[test]
    fn captured_files_match_manifest_hashes() {
        for record in manifest().fixtures {
            assert_eq!(
                sha256(&fixture_path(&record.path)),
                record.sha256,
                "fixture hash mismatch: {}",
                record.path
            );
        }
    }

    #[test]
    fn derived_state_fixtures_change_only_the_documented_state_byte() {
        let manifest = manifest();
        let records: BTreeMap<_, _> = manifest
            .fixtures
            .iter()
            .map(|record| (record.path.as_str(), record))
            .collect();
        let stat_paths: BTreeSet<_> = records
            .values()
            .filter(|record| record.kind == "proc_stat")
            .map(|record| record.path.as_str())
            .collect();
        let indexed_paths: BTreeSet<_> = STATE_FIXTURES.iter().map(|(_, path)| *path).collect();
        let captured_stats: Vec<_> = records
            .values()
            .filter(|record| record.kind == "proc_stat" && record.provenance.kind == "captured")
            .collect();
        let derived_stats: Vec<_> = records
            .values()
            .filter(|record| {
                record.kind == "proc_stat" && record.provenance.kind == "derived_state_byte"
            })
            .collect();

        assert_eq!(stat_paths, indexed_paths);
        assert_eq!(captured_stats.len(), 1);
        assert_eq!(captured_stats[0].state.as_deref(), Some("S"));
        assert_eq!(derived_stats.len(), STATE_FIXTURES.len() - 1);

        for record in derived_stats {
            let source_path = record
                .provenance
                .source
                .as_deref()
                .expect("derived state fixture must identify its captured source");
            let source_record = records
                .get(source_path)
                .unwrap_or_else(|| panic!("missing source manifest record: {source_path}"));
            let mutation = parse_state_mutation(
                record
                    .provenance
                    .mutation
                    .as_deref()
                    .expect("derived state fixture must document its mutation"),
            );
            let source = fixture_bytes(source_path);
            let derived = fixture_bytes(&record.path);
            let differences: Vec<_> = source
                .iter()
                .zip(&derived)
                .enumerate()
                .filter_map(|(index, (left, right))| (left != right).then_some(index))
                .collect();

            assert_eq!(source_record.provenance.kind, "captured");
            assert_eq!(source_record.kind, "proc_stat");
            assert_eq!(source.len(), derived.len());
            assert_eq!(mutation.offset, stat_state_offset(&source));
            assert_eq!(source[mutation.offset], mutation.from);
            assert_eq!(derived[mutation.offset], mutation.to);
            assert_eq!(
                record.state.as_deref(),
                Some(std::str::from_utf8(&[mutation.to]).unwrap())
            );
            assert_eq!(
                differences,
                vec![mutation.offset],
                "{} differs from {} outside the documented state byte",
                record.path,
                source_path
            );
        }

        for (state, path) in STATE_FIXTURES {
            assert_eq!(stat_fixture(state), fixture_bytes(path));
        }
    }

    struct StateMutation {
        offset: usize,
        from: u8,
        to: u8,
    }

    fn fixture_files(root: &Path) -> BTreeSet<String> {
        let mut directories = vec![root.to_path_buf()];
        let mut files = BTreeSet::new();

        while let Some(directory) = directories.pop() {
            for entry in fs::read_dir(&directory)
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", directory.display()))
            {
                let entry = entry.expect("fixture directory entry must be readable");
                let file_type = entry
                    .file_type()
                    .expect("fixture directory entry type must be readable");
                let path = entry.path();

                if file_type.is_dir() {
                    directories.push(path);
                } else if file_type.is_file() {
                    let relative = path
                        .strip_prefix(root)
                        .expect("fixture must remain under its root")
                        .to_string_lossy()
                        .replace(std::path::MAIN_SEPARATOR, "/");
                    if relative != "manifest.json" {
                        files.insert(relative);
                    }
                } else {
                    panic!("unexpected non-file fixture entry: {}", path.display());
                }
            }
        }

        files
    }

    fn sha256(path: &Path) -> String {
        if let Some(hash) = run_hash_command("sha256sum", &[], path) {
            return hash;
        }
        if let Some(hash) = run_hash_command("shasum", &["-a", "256"], path) {
            return hash;
        }
        panic!("neither sha256sum nor shasum is available");
    }

    fn run_hash_command(program: &str, args: &[&str], path: &Path) -> Option<String> {
        let output = Command::new(program).args(args).arg(path).output().ok()?;
        assert!(
            output.status.success(),
            "{program} failed for {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        Some(
            String::from_utf8(output.stdout)
                .expect("SHA-256 command output must be UTF-8")
                .split_whitespace()
                .next()
                .expect("SHA-256 command must print a digest")
                .to_owned(),
        )
    }

    fn parse_state_mutation(documentation: &str) -> StateMutation {
        let documentation = documentation
            .strip_prefix("zero-based byte offset ")
            .expect("state mutation must document a zero-based byte offset");
        let (offset, documentation) = documentation
            .split_once(" changed from ")
            .expect("state mutation must document its original byte");
        let (from, documentation) = documentation
            .split_once(" to ")
            .expect("state mutation must document its replacement byte");
        let (to, suffix) = documentation
            .split_once("; ")
            .expect("state mutation must document that no other bytes changed");

        assert_eq!(suffix, "all other bytes unchanged");
        StateMutation {
            offset: offset.parse().expect("state byte offset must be numeric"),
            from: single_ascii_byte(from),
            to: single_ascii_byte(to),
        }
    }

    fn single_ascii_byte(value: &str) -> u8 {
        let bytes = value.as_bytes();
        assert_eq!(bytes.len(), 1, "state must be one ASCII byte: {value:?}");
        bytes[0]
    }

    fn stat_state_offset(stat: &[u8]) -> usize {
        let close_paren = stat
            .iter()
            .rposition(|byte| *byte == b')')
            .expect("captured stat must contain a comm closing parenthesis");
        let state_offset = close_paren + 2;

        assert_eq!(stat.get(close_paren + 1), Some(&b' '));
        assert_eq!(stat.get(state_offset + 1), Some(&b' '));
        state_offset
    }
}
