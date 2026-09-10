//! File integrity monitoring — persisted baseline + add/modify/delete events.
//!
//! Matches Python bridge semantics: first scan establishes baseline silently;
//! later scans emit events. Bounded depth/count for agent CPU budget.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_HASH_BYTES: u64 = 5_000_000;
const MAX_FILES: usize = 800;
const MAX_DEPTH: usize = 2;
const MAX_EVENTS: usize = 50;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct BaselineEntry {
    hash: String,
    size: u64,
    mtime: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct BaselineFile {
    files: HashMap<String, BaselineEntry>,
}

pub fn scan_fim_events() -> Vec<Value> {
    let watch = default_watch_dirs();
    if watch.is_empty() {
        return vec![];
    }
    let path = baseline_path();
    let mut baseline = load_baseline(&path);
    let first_run = baseline.files.is_empty();
    let mut seen: HashSet<String> = HashSet::new();
    let mut events: Vec<Value> = Vec::new();

    for (file_path, meta) in walk_files(&watch) {
        seen.insert(file_path.clone());
        let hashable = meta.size <= MAX_HASH_BYTES;
        let digest = if hashable {
            sha256_file(Path::new(&file_path)).unwrap_or_default()
        } else {
            String::new()
        };
        match baseline.files.get(&file_path) {
            None => {
                baseline.files.insert(
                    file_path.clone(),
                    BaselineEntry {
                        hash: digest.clone(),
                        size: meta.size,
                        mtime: meta.mtime,
                    },
                );
                if !first_run {
                    events.push(json!({
                        "path": file_path,
                        "status": "added",
                        "hash": digest,
                    }));
                }
            }
            Some(prior) => {
                let changed = if hashable && !prior.hash.is_empty() {
                    digest != prior.hash
                } else {
                    meta.size != prior.size || (meta.mtime - prior.mtime).abs() > 1.0
                };
                if changed {
                    baseline.files.insert(
                        file_path.clone(),
                        BaselineEntry {
                            hash: digest.clone(),
                            size: meta.size,
                            mtime: meta.mtime,
                        },
                    );
                    events.push(json!({
                        "path": file_path,
                        "status": "modified",
                        "hash": digest,
                    }));
                } else if let Some(e) = baseline.files.get_mut(&file_path) {
                    e.mtime = meta.mtime;
                }
            }
        }
        if events.len() >= MAX_EVENTS {
            break;
        }
    }

    // Deletions
    let watch_prefixes: Vec<String> = watch
        .iter()
        .map(|d| {
            let mut s = d.clone();
            if !s.ends_with(std::path::MAIN_SEPARATOR) {
                s.push(std::path::MAIN_SEPARATOR);
            }
            s
        })
        .collect();
    let keys: Vec<String> = baseline.files.keys().cloned().collect();
    for key in keys {
        if seen.contains(&key) {
            continue;
        }
        if !watch_prefixes.iter().any(|p| key.starts_with(p)) {
            continue;
        }
        if Path::new(&key).exists() {
            continue;
        }
        baseline.files.remove(&key);
        events.push(json!({ "path": key, "status": "deleted" }));
        if events.len() >= MAX_EVENTS {
            break;
        }
    }

    save_baseline(&path, &baseline);
    if events.len() > MAX_EVENTS {
        events.truncate(MAX_EVENTS);
    }
    events
}

pub fn fim_summary(events: &[Value], tracked: Option<usize>) -> Value {
    let mut added = 0;
    let mut modified = 0;
    let mut deleted = 0;
    for e in events {
        match e.get("status").and_then(|v| v.as_str()) {
            Some("added") => added += 1,
            Some("modified") => modified += 1,
            Some("deleted") => deleted += 1,
            _ => {}
        }
    }
    json!({
        "collected": true,
        "reason": "",
        "tracked_files": tracked.unwrap_or(0),
        "baseline_established": true,
        "added": added,
        "modified": modified,
        "deleted": deleted,
        "events": events,
    })
}

struct FileMeta {
    size: u64,
    mtime: f64,
}

fn walk_files(dirs: &[String]) -> Vec<(String, FileMeta)> {
    let mut out = Vec::new();
    for base in dirs {
        let base_path = Path::new(base);
        let base_depth = base_path.components().count();
        let mut stack = vec![base_path.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let depth = dir.components().count().saturating_sub(base_depth);
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for ent in entries.flatten() {
                let p = ent.path();
                let Ok(ft) = ent.file_type() else {
                    continue;
                };
                if ft.is_dir() {
                    if depth < MAX_DEPTH {
                        stack.push(p);
                    }
                    continue;
                }
                if !ft.is_file() {
                    continue;
                }
                let Ok(meta) = ent.metadata() else {
                    continue;
                };
                let mtime = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs_f64())
                    .unwrap_or(0.0);
                out.push((
                    p.to_string_lossy().into_owned(),
                    FileMeta {
                        size: meta.len(),
                        mtime,
                    },
                ));
                if out.len() >= MAX_FILES {
                    return out;
                }
            }
        }
    }
    out
}

fn sha256_file(path: &Path) -> Option<String> {
    let mut f = fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > MAX_HASH_BYTES {
            return Some(String::new());
        }
        hasher.update(&buf[..n]);
    }
    Some(hex::encode(hasher.finalize()))
}

fn default_watch_dirs() -> Vec<String> {
    let mut out = Vec::new();
    let mut push = |p: PathBuf| {
        if p.is_dir() {
            let s = p.to_string_lossy().into_owned();
            if !out.iter().any(|x| x == &s) {
                out.push(s);
            }
        }
    };
    if let Some(home) = dirs::home_dir() {
        push(home.clone());
        push(home.join("Downloads"));
        push(home.join("Desktop"));
    }
    #[cfg(windows)]
    {
        if let Ok(t) = std::env::var("TEMP") {
            push(PathBuf::from(t));
        }
        if let Ok(t) = std::env::var("TMP") {
            push(PathBuf::from(t));
        }
    }
    #[cfg(unix)]
    {
        push(PathBuf::from("/tmp"));
        push(PathBuf::from("/var/tmp"));
    }
    out
}

fn baseline_path() -> PathBuf {
    let root = std::env::var("SECURAIQ_AGENT_DATA_DIR")
        .or_else(|_| std::env::var("SECURAIQ_DATA_DIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".securaiq")
                .join("agent")
        });
    let _ = fs::create_dir_all(&root);
    root.join("fim_baseline.json")
}

fn load_baseline(path: &Path) -> BaselineFile {
    let Ok(text) = fs::read_to_string(path) else {
        return BaselineFile::default();
    };
    // Support both {files:{...}} and flat {path: entry} from older experiments.
    if let Ok(v) = serde_json::from_str::<BaselineFile>(&text) {
        return v;
    }
    if let Ok(map) = serde_json::from_str::<HashMap<String, BaselineEntry>>(&text) {
        return BaselineFile { files: map };
    }
    BaselineFile::default()
}

fn save_baseline(path: &Path, baseline: &BaselineFile) {
    let Ok(text) = serde_json::to_string(baseline) else {
        return;
    };
    let tmp = path.with_extension("json.tmp");
    if fs::write(&tmp, text).is_ok() {
        let _ = fs::rename(&tmp, path);
    }
}

#[allow(dead_code)]
fn _now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}
