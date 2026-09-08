use clap::{Parser, Subcommand};
use ptdfctl::{dump_segment, inspect_segment, verify_segment};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "ptdfctl", about = "PTDF command-line tool", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Operate on a single segment file directly (no metadata store
    /// required — useful for local debugging of a segment produced by the
    /// recorder or copied down from storage).
    Segment {
        #[command(subcommand)]
        action: SegmentAction,
    },
}

#[derive(Subcommand)]
enum SegmentAction {
    /// Print a summary: event count, compression flag, counts by kind.
    Inspect { path: PathBuf },
    /// Print one line per event.
    Dump {
        path: PathBuf,
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Read the entire segment, verifying every checksum; exits non-zero
    /// on the first corruption found.
    Verify { path: PathBuf },
}

fn main() -> ExitCode {
    let _ = ptdf_logging::init(ptdf_logging::LoggingConfig::dev_default());
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Segment { action } => match action {
            SegmentAction::Inspect { path } => inspect_segment(&path).map(|summary| {
                println!("compressed: {}", summary.compressed);
                println!("event_count: {}", summary.event_count);
                for (kind, count) in &summary.counts_by_kind {
                    println!("  {kind}: {count}");
                }
            }),
            SegmentAction::Dump { path, limit } => dump_segment(&path, limit).map(|lines| {
                for line in lines {
                    println!("{line}");
                }
            }),
            SegmentAction::Verify { path } => verify_segment(&path).map(|count| {
                println!("OK: {count} events verified");
            }),
        },
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
