//! Turns Criterion output into actionable reports.
//!
//! - `benchmarks/reports/latest/summary.json` — machine-readable stats per
//!   bench (mean/median/stddev ns, input bytes, MiB/s), usable as a baseline.
//! - `benchmarks/reports/latest/summary.md` — per-scenario pivot tables
//!   (rows = workload, columns = implementation) with throughput and a
//!   slowdown ratio versus the sacp-cbor reference implementation.
//!
//! Regression workflow:
//!
//! ```bash
//! cargo run -p bench_harness --bin report                      # snapshot
//! cp reports/latest/summary.json /tmp/baseline.json
//! # ... optimize ...
//! cargo bench
//! cargo run -p bench_harness --bin report -- \
//!     --baseline /tmp/baseline.json --threshold 5 --fail-on-regress
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::{Deserialize, Serialize};

/// Implementations treated as "the sacp-cbor way" for a scenario; the first
/// one present in a group becomes the ratio reference column.
const REFERENCE_IMPLS: &[&str] = &[
    "sacp-zerocopy",
    "sacp-editor",
    "sacp-cbor",
    "sacp-validate",
    "sacp-stream",
    "sacp-native",
    "sacp-trusted",
];

#[derive(Debug, Default, Serialize, Deserialize)]
struct Summary {
    benches: BTreeMap<String, BenchStats>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BenchStats {
    mean_ns: f64,
    median_ns: f64,
    std_dev_ns: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    input_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mib_per_s: Option<f64>,
}

struct Args {
    baseline: Option<PathBuf>,
    threshold_pct: f64,
    fail_on_regress: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        baseline: None,
        threshold_pct: 5.0,
        fail_on_regress: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--baseline" => {
                let v = it.next().ok_or("--baseline requires a path")?;
                args.baseline = Some(PathBuf::from(v));
            }
            "--threshold" => {
                let v = it.next().ok_or("--threshold requires a percentage")?;
                args.threshold_pct = v
                    .parse::<f64>()
                    .map_err(|e| format!("invalid --threshold {v}: {e}"))?;
            }
            "--fail-on-regress" => args.fail_on_regress = true,
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(args)
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("report: {e}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let args = parse_args()?;

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("criterion");
    let summary = collect_summary(&root)?;

    let baseline = match &args.baseline {
        Some(path) => {
            let data = fs::read_to_string(path)
                .map_err(|e| format!("read baseline {}: {e}", path.display()))?;
            Some(serde_json::from_str::<Summary>(&data)?)
        }
        None => None,
    };

    let comparison = baseline
        .as_ref()
        .map(|base| compare(base, &summary, args.threshold_pct));

    let reports_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("reports")
        .join("latest");
    fs::create_dir_all(&reports_dir)?;

    let json_path = reports_dir.join("summary.json");
    fs::write(&json_path, serde_json::to_vec_pretty(&summary)?)?;

    let md_path = reports_dir.join("summary.md");
    let mut md = render_markdown(&summary);
    if let Some(cmp) = &comparison {
        md.push_str(&render_comparison(cmp, args.threshold_pct));
    }
    fs::write(&md_path, &md)?;

    println!("Wrote {} and {}", json_path.display(), md_path.display());

    if let Some(cmp) = &comparison {
        for row in &cmp.rows {
            if row.delta_pct.abs() >= args.threshold_pct {
                println!(
                    "{} {}: {:+.1}% ({} -> {})",
                    if row.delta_pct > 0.0 {
                        "REGRESS"
                    } else {
                        "improve"
                    },
                    row.name,
                    row.delta_pct,
                    fmt_time(row.base_median_ns),
                    fmt_time(row.new_median_ns),
                );
            }
        }
        let regressed = cmp.rows.iter().any(|r| r.delta_pct >= args.threshold_pct);
        if regressed && args.fail_on_regress {
            eprintln!(
                "report: regressions beyond {:.1}% detected",
                args.threshold_pct
            );
            return Ok(ExitCode::from(1));
        }
    }

    Ok(ExitCode::SUCCESS)
}

/* =========================
 * Criterion output collection
 * ========================= */

fn collect_summary(root: &Path) -> Result<Summary, Box<dyn std::error::Error>> {
    let mut summary = Summary::default();
    if !root.exists() {
        return Ok(summary);
    }
    collect_estimates(root, root, &mut summary.benches)?;
    Ok(summary)
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

        let input_bytes = read_throughput_bytes(&parent.join("benchmark.json"));
        let mib_per_s = input_bytes.and_then(|bytes| {
            if median > 0.0 {
                Some(bytes as f64 / (median * 1e-9) / (1024.0 * 1024.0))
            } else {
                None
            }
        });

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
                input_bytes,
                mib_per_s,
            },
        );
    }
    Ok(())
}

fn read_throughput_bytes(path: &Path) -> Option<u64> {
    let data = fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&data).ok()?;
    v["throughput"]["Bytes"].as_u64()
}

/* =========================
 * Markdown rendering
 * ========================= */

fn fmt_time(ns: f64) -> String {
    if ns < 1_000.0 {
        format!("{ns:.0} ns")
    } else if ns < 1_000_000.0 {
        format!("{:.2} µs", ns / 1_000.0)
    } else if ns < 1_000_000_000.0 {
        format!("{:.2} ms", ns / 1_000_000.0)
    } else {
        format!("{:.2} s", ns / 1_000_000_000.0)
    }
}

fn fmt_rate(mib_per_s: f64) -> String {
    if mib_per_s >= 1024.0 {
        format!("{:.2} GiB/s", mib_per_s / 1024.0)
    } else {
        format!("{mib_per_s:.0} MiB/s")
    }
}

/// Split a bench name into (group, implementation, workload) if it follows
/// the uniform `scenario/impl/workload` scheme.
fn split3(name: &str) -> Option<(&str, &str, &str)> {
    let mut parts = name.splitn(3, '/');
    let a = parts.next()?;
    let b = parts.next()?;
    let c = parts.next()?;
    if c.contains('/') {
        return None;
    }
    Some((a, b, c))
}

fn render_markdown(summary: &Summary) -> String {
    let mut out = String::new();
    out.push_str("# Benchmark Summary\n\n");
    out.push_str(
        "Cells show median time (throughput where available). The `×N` ratio is the \
         slowdown relative to the sacp-cbor reference implementation in that scenario \
         (>1 means slower than sacp-cbor).\n",
    );

    // group -> impl -> workload -> stats
    let mut groups: BTreeMap<&str, BTreeMap<&str, BTreeMap<&str, &BenchStats>>> = BTreeMap::new();
    let mut flat: Vec<(&str, &BenchStats)> = Vec::new();

    for (name, stats) in &summary.benches {
        match split3(name) {
            Some((group, imp, workload)) => {
                groups
                    .entry(group)
                    .or_default()
                    .entry(imp)
                    .or_default()
                    .insert(workload, stats);
            }
            None => flat.push((name, stats)),
        }
    }

    for (group, impls) in &groups {
        out.push_str(&format!("\n## {group}\n\n"));

        let reference = REFERENCE_IMPLS
            .iter()
            .copied()
            .find(|r| impls.contains_key(r));

        // Reference column first, the rest in alphabetical order.
        let mut columns: Vec<&str> = impls.keys().copied().collect();
        if let Some(reference) = reference {
            columns.retain(|c| *c != reference);
            columns.insert(0, reference);
        }

        let workloads: BTreeSet<&str> = impls
            .values()
            .flat_map(|by_workload| by_workload.keys().copied())
            .collect();

        out.push_str(&format!("| workload | {} |\n", columns.join(" | ")));
        out.push_str(&format!("| --- |{}\n", " ---: |".repeat(columns.len())));

        for workload in workloads {
            let ref_median = reference
                .and_then(|r| impls.get(r))
                .and_then(|m| m.get(workload))
                .map(|s| s.median_ns);

            let mut row = format!("| {workload} |");
            for column in &columns {
                let cell = match impls.get(column).and_then(|m| m.get(workload)) {
                    Some(stats) => {
                        let mut cell = fmt_time(stats.median_ns);
                        if let Some(rate) = stats.mib_per_s {
                            cell.push_str(&format!(", {}", fmt_rate(rate)));
                        }
                        match ref_median {
                            Some(ref_ns) if ref_ns > 0.0 && Some(*column) != reference => {
                                cell.push_str(&format!(" (×{:.2})", stats.median_ns / ref_ns));
                            }
                            _ => {}
                        }
                        cell
                    }
                    None => "—".to_string(),
                };
                row.push_str(&format!(" {cell} |"));
            }
            row.push('\n');
            out.push_str(&row);
        }
    }

    if !flat.is_empty() {
        out.push_str("\n## other\n\n");
        out.push_str("| bench | median | mean | std dev |\n");
        out.push_str("| --- | ---: | ---: | ---: |\n");
        for (name, stats) in flat {
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                name,
                fmt_time(stats.median_ns),
                fmt_time(stats.mean_ns),
                fmt_time(stats.std_dev_ns)
            ));
        }
    }

    out
}

/* =========================
 * Baseline comparison
 * ========================= */

struct ComparisonRow {
    name: String,
    base_median_ns: f64,
    new_median_ns: f64,
    delta_pct: f64,
}

struct Comparison {
    rows: Vec<ComparisonRow>,
}

fn compare(base: &Summary, new: &Summary, _threshold_pct: f64) -> Comparison {
    let mut rows = Vec::new();
    for (name, new_stats) in &new.benches {
        let Some(base_stats) = base.benches.get(name) else {
            continue;
        };
        if base_stats.median_ns <= 0.0 {
            continue;
        }
        let delta_pct = (new_stats.median_ns - base_stats.median_ns) / base_stats.median_ns * 100.0;
        rows.push(ComparisonRow {
            name: name.clone(),
            base_median_ns: base_stats.median_ns,
            new_median_ns: new_stats.median_ns,
            delta_pct,
        });
    }
    rows.sort_by(|a, b| b.delta_pct.total_cmp(&a.delta_pct));
    Comparison { rows }
}

fn render_comparison(cmp: &Comparison, threshold_pct: f64) -> String {
    let mut out = String::new();
    out.push_str("\n## Comparison vs baseline\n\n");
    let notable: Vec<&ComparisonRow> = cmp
        .rows
        .iter()
        .filter(|r| r.delta_pct.abs() >= threshold_pct)
        .collect();
    if notable.is_empty() {
        out.push_str(&format!(
            "No benches changed by {threshold_pct:.1}% or more.\n"
        ));
        return out;
    }
    out.push_str("| bench | baseline | now | Δ median |\n");
    out.push_str("| --- | ---: | ---: | ---: |\n");
    for row in notable {
        out.push_str(&format!(
            "| {} | {} | {} | {:+.1}% |\n",
            row.name,
            fmt_time(row.base_median_ns),
            fmt_time(row.new_median_ns),
            row.delta_pct
        ));
    }
    out
}
