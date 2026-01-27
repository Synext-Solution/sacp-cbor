use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

#[derive(Debug, Serialize)]
struct Summary {
    benches: BTreeMap<String, BenchStats>,
}

#[derive(Debug, Serialize)]
struct BenchStats {
    mean_ns: f64,
    median_ns: f64,
    std_dev_ns: f64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("criterion");
    let summary = collect_summary(&root)?;

    let reports_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("reports")
        .join("latest");
    fs::create_dir_all(&reports_dir)?;

    let json_path = reports_dir.join("summary.json");
    fs::write(&json_path, serde_json::to_vec_pretty(&summary)?)?;

    let md_path = reports_dir.join("summary.md");
    fs::write(&md_path, render_markdown(&summary))?;

    println!("Wrote {} and {}", json_path.display(), md_path.display());
    Ok(())
}

fn collect_summary(root: &Path) -> Result<Summary, Box<dyn std::error::Error>> {
    let mut benches = BTreeMap::new();
    if !root.exists() {
        return Ok(Summary { benches });
    }
    collect_estimates(root, root, &mut benches)?;

    Ok(Summary { benches })
}

fn collect_estimates(
    root: &Path,
    dir: &Path,
    benches: &mut BTreeMap<String, BenchStats>,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_estimates(root, &path, benches)?;
            continue;
        }
        if path.file_name().and_then(|s| s.to_str()) != Some("estimates.json") {
            continue;
        }
        let parent = match path.parent() {
            Some(parent) => parent,
            None => continue,
        };
        if parent.file_name().and_then(|s| s.to_str()) != Some("new") {
            continue;
        }
        let bench_dir = match parent.parent() {
            Some(dir) => dir,
            None => continue,
        };
        let data = fs::read_to_string(&path)?;
        let v: serde_json::Value = serde_json::from_str(&data)?;
        let mean = v["mean"]["point_estimate"].as_f64().unwrap_or(0.0);
        let median = v["median"]["point_estimate"].as_f64().unwrap_or(0.0);
        let std_dev = v["std_dev"]["point_estimate"].as_f64().unwrap_or(0.0);
        let name = bench_dir
            .strip_prefix(root)?
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");
        benches.insert(
            name,
            BenchStats {
                mean_ns: mean,
                median_ns: median,
                std_dev_ns: std_dev,
            },
        );
    }
    Ok(())
}

fn render_markdown(summary: &Summary) -> String {
    let mut out = String::new();
    out.push_str("# Benchmark Summary\n\n");
    out.push_str("| Bench | Mean (ns) | Median (ns) | Std Dev (ns) |\n");
    out.push_str("| --- | ---: | ---: | ---: |\n");
    for (name, stats) in &summary.benches {
        out.push_str(&format!(
            "| {} | {:.2} | {:.2} | {:.2} |\n",
            name, stats.mean_ns, stats.median_ns, stats.std_dev_ns
        ));
    }
    out
}
