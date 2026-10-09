//! Synthetic `WorkBudget` counter microbenchmark.
//!
//! Run with:
//! `cargo run --release -p formatkit-core --example work_budget_baseline -- 51 1000000`
//!
//! Arguments are measured rounds and iterations per route. Five unreported
//! warm-up rounds run first. Every measured round alternates direct/candidate
//! order. Output is versioned JSONL suitable for capture and comparison.

use std::hint::black_box;
use std::process::Command;
use std::time::{Duration, Instant};

use formatkit_core::{MemoryRangeSource, RangeSource, WorkBudget, WorkLimits, WorkResource};

const DEFAULT_ROUNDS: usize = 51;
const DEFAULT_ITERATIONS: u64 = 1_000_000;
const WARMUP_ROUNDS: usize = 5;

#[derive(Clone, Copy)]
enum Case {
    Charge,
    Usage,
    ResidentAcquireDrop,
    ResidentResize,
    SourceRead64K,
}

impl Case {
    const ALL: [Self; 5] = [
        Self::Charge,
        Self::Usage,
        Self::ResidentAcquireDrop,
        Self::ResidentResize,
        Self::SourceRead64K,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Charge => "charge",
            Self::Usage => "usage_snapshot",
            Self::ResidentAcquireDrop => "resident_acquire_drop",
            Self::ResidentResize => "resident_resize",
            Self::SourceRead64K => "source_read_64k",
        }
    }

    fn iterations(self, configured: u64) -> u64 {
        match self {
            Self::SourceRead64K => configured.div_ceil(4096).max(1),
            _ => configured,
        }
    }
}

#[derive(Clone, Copy)]
enum Route {
    Direct,
    WorkBudget,
}

impl Route {
    const fn label(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::WorkBudget => "work_budget",
        }
    }
}

#[derive(Clone, Copy)]
struct Observation {
    elapsed: Duration,
    checksum: u64,
}

#[derive(Clone, Copy)]
struct DirectLimits {
    values: [Option<u64>; 7],
    depth: Option<u64>,
    resident_bytes: Option<u64>,
}

#[derive(Clone, Copy)]
struct DirectUsage {
    limits: DirectLimits,
    spent: [u64; 7],
    active_depth: u64,
    peak_depth: u64,
    resident_bytes: u64,
    peak_resident_bytes: u64,
    io_completed_bytes: u64,
    complete_logical_read_accounting: bool,
    complete_io_accounting: bool,
    complete_resident_accounting: bool,
    cancellation_requested: bool,
    cancellation_observed: bool,
}

struct DirectBudget {
    limit: u64,
    spent: u64,
    resident_limit: u64,
    resident_bytes: u64,
    peak_resident_bytes: u64,
}

impl DirectBudget {
    const fn new(limit: u64) -> Self {
        Self {
            limit,
            spent: 0,
            resident_limit: limit,
            resident_bytes: 0,
            peak_resident_bytes: 0,
        }
    }

    #[inline(never)]
    fn charge(&mut self, amount: u64) {
        let requested = self
            .spent
            .checked_add(amount)
            .expect("direct charge overflow");
        assert!(requested <= self.limit);
        self.spent = requested;
    }

    #[inline(never)]
    fn usage(&self) -> DirectUsage {
        DirectUsage {
            limits: DirectLimits {
                values: [Some(self.limit); 7],
                depth: None,
                resident_bytes: Some(self.resident_limit),
            },
            spent: [self.spent; 7],
            active_depth: 0,
            peak_depth: 0,
            resident_bytes: self.resident_bytes,
            peak_resident_bytes: self.peak_resident_bytes,
            io_completed_bytes: 0,
            complete_logical_read_accounting: true,
            complete_io_accounting: true,
            complete_resident_accounting: true,
            cancellation_requested: false,
            cancellation_observed: false,
        }
    }

    #[inline(never)]
    fn reserve(&mut self, amount: u64) -> DirectReservation<'_> {
        let requested = self
            .resident_bytes
            .checked_add(amount)
            .expect("direct resident overflow");
        assert!(requested <= self.resident_limit);
        self.resident_bytes = requested;
        self.peak_resident_bytes = self.peak_resident_bytes.max(requested);
        DirectReservation {
            budget: self,
            amount,
        }
    }
}

struct DirectReservation<'a> {
    budget: &'a mut DirectBudget,
    amount: u64,
}

impl DirectReservation<'_> {
    #[inline(never)]
    fn grow(&mut self, additional: u64) {
        let requested = self
            .budget
            .resident_bytes
            .checked_add(additional)
            .expect("direct resident overflow");
        let amount = self
            .amount
            .checked_add(additional)
            .expect("direct reservation overflow");
        assert!(requested <= self.budget.resident_limit);
        self.budget.resident_bytes = requested;
        self.budget.peak_resident_bytes = self.budget.peak_resident_bytes.max(requested);
        self.amount = amount;
    }

    #[inline(never)]
    fn release(&mut self, amount: u64) {
        assert!(amount <= self.amount);
        self.amount -= amount;
        self.budget.resident_bytes -= amount;
    }
}

impl Drop for DirectReservation<'_> {
    #[inline(never)]
    fn drop(&mut self) {
        self.budget.resident_bytes -= self.amount;
    }
}

#[inline(never)]
fn work_charge(budget: &mut WorkBudget, amount: u64) {
    budget
        .charge(WorkResource::Nodes, amount)
        .expect("measured charge stays within its limit");
}

fn run_direct(case: Case, iterations: u64) -> Observation {
    let limit = iterations.saturating_add(1);
    let mut budget = DirectBudget::new(limit);
    if matches!(case, Case::Usage) {
        budget.charge(1);
    }
    let source = matches!(case, Case::SourceRead64K).then(|| vec![0x5a; 64 * 1024]);
    let mut output = matches!(case, Case::SourceRead64K).then(|| vec![0u8; 64 * 1024]);
    let mut data_checksum = 0u64;
    let started = Instant::now();
    match case {
        Case::Charge => {
            for _ in 0..iterations {
                budget.charge(black_box(1));
                black_box(&budget);
            }
        }
        Case::Usage => {
            for _ in 0..iterations {
                black_box(budget.usage());
            }
        }
        Case::ResidentAcquireDrop => {
            for _ in 0..iterations {
                let reservation = budget.reserve(black_box(1));
                black_box(&reservation);
                drop(reservation);
            }
        }
        Case::ResidentResize => {
            for _ in 0..iterations {
                let mut reservation = budget.reserve(0);
                reservation.grow(black_box(1));
                reservation.release(black_box(1));
                black_box(&reservation);
            }
        }
        Case::SourceRead64K => {
            let source = source.as_deref().expect("source-read payload exists");
            let output = output.as_deref_mut().expect("source-read output exists");
            for _ in 0..iterations {
                output.copy_from_slice(source);
                black_box(&output);
            }
            data_checksum = u64::from(output[0]) + u64::from(output[output.len() - 1]);
        }
    }
    let elapsed = started.elapsed();
    let usage = budget.usage();
    Observation {
        elapsed,
        checksum: usage.spent[5]
            .wrapping_add(usage.resident_bytes)
            .wrapping_add(usage.peak_resident_bytes)
            .wrapping_add(usage.limits.values[5].unwrap_or(0))
            .wrapping_add(usage.limits.depth.unwrap_or(0))
            .wrapping_add(usage.limits.resident_bytes.unwrap_or(0))
            .wrapping_add(usage.active_depth)
            .wrapping_add(usage.peak_depth)
            .wrapping_add(usage.io_completed_bytes)
            .wrapping_add(u64::from(usage.complete_logical_read_accounting))
            .wrapping_add(u64::from(usage.complete_io_accounting))
            .wrapping_add(u64::from(usage.complete_resident_accounting))
            .wrapping_add(u64::from(usage.cancellation_requested))
            .wrapping_add(u64::from(usage.cancellation_observed))
            .wrapping_add(data_checksum),
    }
}

fn run_work_budget(case: Case, iterations: u64) -> Observation {
    let limit = iterations.saturating_add(1);
    let logical_limit = iterations.saturating_mul(64 * 1024);
    let mut budget = WorkBudget::new(
        WorkLimits::unlimited()
            .with(WorkResource::Nodes, limit)
            .with(WorkResource::LogicalReadBytes, logical_limit)
            .with_resident_bytes(limit),
    );
    if matches!(case, Case::Usage) {
        work_charge(&mut budget, 1);
    }
    let source = matches!(case, Case::SourceRead64K)
        .then(|| MemoryRangeSource::new(vec![0x5a; 64 * 1024], "work-budget benchmark"));
    let mut output = matches!(case, Case::SourceRead64K).then(|| vec![0u8; 64 * 1024]);
    let mut data_checksum = 0u64;
    let started = Instant::now();
    match case {
        Case::Charge => {
            for _ in 0..iterations {
                work_charge(&mut budget, black_box(1));
                black_box(&budget);
            }
        }
        Case::Usage => {
            for _ in 0..iterations {
                black_box(budget.usage());
            }
        }
        Case::ResidentAcquireDrop => {
            for _ in 0..iterations {
                let reservation = budget
                    .reserve_resident(black_box(1))
                    .expect("measured reservation stays within its limit");
                black_box(&reservation);
                drop(reservation);
            }
        }
        Case::ResidentResize => {
            for _ in 0..iterations {
                let mut reservation = budget
                    .reserve_resident(0)
                    .expect("zero-byte reservation stays within its limit");
                reservation
                    .try_grow(black_box(1))
                    .expect("measured growth stays within its limit");
                reservation
                    .release(black_box(1))
                    .expect("measured release stays within its reservation");
                black_box(&reservation);
            }
        }
        Case::SourceRead64K => {
            let source = source.as_ref().expect("source-read source exists");
            let output = output.as_deref_mut().expect("source-read output exists");
            for _ in 0..iterations {
                source
                    .read_exact_into(0, output, &mut budget)
                    .expect("measured source read stays within its limit");
                black_box(&output);
            }
            data_checksum = u64::from(output[0]) + u64::from(output[output.len() - 1]);
        }
    }
    let elapsed = started.elapsed();
    let usage = budget.usage();
    Observation {
        elapsed,
        checksum: usage
            .spent(WorkResource::Nodes)
            .wrapping_add(usage.resident_bytes())
            .wrapping_add(usage.peak_resident_bytes())
            .wrapping_add(usage.limit(WorkResource::Nodes).unwrap_or(0))
            .wrapping_add(usage.depth_limit().unwrap_or(0))
            .wrapping_add(usage.resident_bytes_limit().unwrap_or(0))
            .wrapping_add(usage.active_depth())
            .wrapping_add(usage.peak_depth())
            .wrapping_add(usage.io_completed_bytes())
            .wrapping_add(u64::from(usage.complete_logical_read_accounting()))
            .wrapping_add(u64::from(usage.complete_io_accounting()))
            .wrapping_add(u64::from(usage.complete_resident_accounting()))
            .wrapping_add(u64::from(usage.cancellation_requested()))
            .wrapping_add(u64::from(usage.cancellation_observed()))
            .wrapping_add(data_checksum),
    }
}

fn run(case: Case, route: Route, iterations: u64) -> Observation {
    match route {
        Route::Direct => run_direct(case, iterations),
        Route::WorkBudget => run_work_budget(case, iterations),
    }
}

fn percentile(sorted: &[u128], numerator: usize, denominator: usize) -> u128 {
    let rank = sorted
        .len()
        .saturating_mul(numerator)
        .div_ceil(denominator)
        .max(1);
    sorted[rank - 1]
}

fn median(sorted: &[u128]) -> u128 {
    let middle = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        sorted[middle - 1]
            .checked_add(sorted[middle])
            .expect("duration sum fits u128")
            / 2
    } else {
        sorted[middle]
    }
}

fn overhead_percent(baseline: u128, candidate: u128) -> f64 {
    // Preserve valid JSON even when an extremely small configured run falls
    // below the platform clock's resolution.
    (candidate as f64 / baseline.max(1) as f64 - 1.0) * 100.0
}

fn median_f64(sorted: &[f64]) -> f64 {
    let middle = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        (sorted[middle - 1] + sorted[middle]) / 2.0
    } else {
        sorted[middle]
    }
}

fn percentile_f64(sorted: &[f64], numerator: usize, denominator: usize) -> f64 {
    let rank = sorted
        .len()
        .saturating_mul(numerator)
        .div_ceil(denominator)
        .max(1);
    sorted[rank - 1]
}

fn command_output(program: &str, arguments: &[&str]) -> String {
    Command::new(program)
        .args(arguments)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|output| output.trim().to_owned())
        .filter(|output| !output.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn git_dirty_state() -> &'static str {
    match Command::new("git")
        .args(["status", "--porcelain=v1", "--untracked-files=normal"])
        .output()
    {
        Ok(output) if output.status.success() && output.stdout.is_empty() => "clean",
        Ok(output) if output.status.success() => "dirty",
        _ => "unknown",
    }
}

fn json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                write!(escaped, "\\u{:04x}", character as u32)
                    .expect("writing to a String cannot fail");
            }
            character => escaped.push(character),
        }
    }
    escaped.push('"');
    escaped
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let rounds = arguments
        .next()
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(DEFAULT_ROUNDS);
    let iterations = arguments
        .next()
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(DEFAULT_ITERATIONS);
    if arguments.next().is_some() || rounds == 0 || iterations == 0 {
        return Err("usage: work_budget_baseline [positive-rounds] [positive-iterations]".into());
    }

    let rustc = command_output("rustc", &["-vV"]);
    let compiler = rustc.lines().next().unwrap_or("unknown");
    let target = rustc
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .unwrap_or("unknown");
    let commit = command_output("git", &["rev-parse", "HEAD"]);
    let git_dirty = git_dirty_state();
    println!(
        "{{\"schema\":\"formatkit.work-budget-baseline.v1\",\"kind\":\"metadata\",\"rounds\":{rounds},\"warmup_rounds\":{WARMUP_ROUNDS},\"configured_iterations\":{iterations},\"release\":{},\"alternating_order\":true,\"percentile\":\"nearest-rank\",\"compiler\":{},\"target\":{},\"os\":{},\"arch\":{},\"commit\":{},\"git_dirty\":{},\"diagnostic_median_reference_percent\":3.0,\"diagnostic_p95_reference_percent\":5.0,\"note\":\"single-threaded synthetic diagnostic; configuration and JSON shape are reproducible but timings are not deterministic; direct route mirrors bookkeeping or byte-copy shape; setup excluded; resident acquire/drop intentionally includes private Arc ledger identity clone/drop overhead; phase operation-level gate remains separate\"}}",
        !cfg!(debug_assertions),
        json_string(compiler),
        json_string(target),
        json_string(std::env::consts::OS),
        json_string(std::env::consts::ARCH),
        json_string(&commit),
        json_string(git_dirty),
    );

    for case in Case::ALL {
        let case_iterations = case.iterations(iterations);
        for warmup in 0..WARMUP_ROUNDS {
            let routes = if warmup.is_multiple_of(2) {
                [Route::Direct, Route::WorkBudget]
            } else {
                [Route::WorkBudget, Route::Direct]
            };
            for route in routes {
                black_box(run(case, route, case_iterations));
            }
        }

        let mut direct = Vec::with_capacity(rounds);
        let mut candidate = Vec::with_capacity(rounds);
        let mut paired_overheads = Vec::with_capacity(rounds);
        for round in 0..rounds {
            let routes = if round.is_multiple_of(2) {
                [Route::Direct, Route::WorkBudget]
            } else {
                [Route::WorkBudget, Route::Direct]
            };
            let mut checksums = [None, None];
            for (order, route) in routes.into_iter().enumerate() {
                let observation = run(case, route, case_iterations);
                let elapsed_ns = observation.elapsed.as_nanos();
                match route {
                    Route::Direct => {
                        direct.push(elapsed_ns);
                        checksums[0] = Some(observation.checksum);
                    }
                    Route::WorkBudget => {
                        candidate.push(elapsed_ns);
                        checksums[1] = Some(observation.checksum);
                    }
                }
                println!(
                    "{{\"schema\":\"formatkit.work-budget-baseline.v1\",\"kind\":\"observation\",\"case\":\"{}\",\"route\":\"{}\",\"round\":{round},\"order\":{order},\"iterations\":{case_iterations},\"elapsed_ns\":{elapsed_ns},\"checksum\":{}}}",
                    case.label(),
                    route.label(),
                    observation.checksum,
                );
            }
            assert_eq!(
                checksums[0],
                checksums[1],
                "{} checksum drift",
                case.label()
            );
            paired_overheads.push(overhead_percent(direct[round], candidate[round]));
        }

        direct.sort_unstable();
        candidate.sort_unstable();
        paired_overheads.sort_by(f64::total_cmp);
        let direct_median = median(&direct);
        let candidate_median = median(&candidate);
        let direct_p95 = percentile(&direct, 95, 100);
        let candidate_p95 = percentile(&candidate, 95, 100);
        let ratio_of_medians = overhead_percent(direct_median, candidate_median);
        let paired_median_overhead = median_f64(&paired_overheads);
        let paired_p95_overhead = percentile_f64(&paired_overheads, 95, 100);
        let direct_ns_per_iteration = direct_median as f64 / case_iterations as f64;
        let candidate_ns_per_iteration = candidate_median as f64 / case_iterations as f64;
        println!(
            "{{\"schema\":\"formatkit.work-budget-baseline.v1\",\"kind\":\"summary\",\"case\":\"{}\",\"baseline\":\"direct\",\"candidate\":\"work_budget\",\"rounds\":{rounds},\"iterations\":{case_iterations},\"baseline_median_ns\":{direct_median},\"candidate_median_ns\":{candidate_median},\"baseline_median_ns_per_iteration\":{direct_ns_per_iteration:.6},\"candidate_median_ns_per_iteration\":{candidate_ns_per_iteration:.6},\"ratio_of_medians_overhead_percent\":{ratio_of_medians:.6},\"paired_median_overhead_percent\":{paired_median_overhead:.6},\"diagnostic_median_within_reference\":{},\"baseline_p95_ns\":{direct_p95},\"candidate_p95_ns\":{candidate_p95},\"paired_p95_overhead_percent\":{paired_p95_overhead:.6},\"diagnostic_p95_within_reference\":{},\"phase_operation_gate\":\"open\"}}",
            case.label(),
            paired_median_overhead <= 3.0,
            paired_p95_overhead <= 5.0,
        );
    }

    Ok(())
}
