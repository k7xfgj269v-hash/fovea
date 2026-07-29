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
