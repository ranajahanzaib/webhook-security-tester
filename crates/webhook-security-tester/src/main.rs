use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::{collections::HashSet, fs, path::PathBuf};
use webhook_security_tester::{
    config::{Config, Profile},
    fixture::{self, Category},
    runner,
};

const GITHUB_SAMPLE: &str = include_str!("../examples/webhook-security-tester.toml");
#[derive(Parser)]
#[command(
    name = "webhook-security-tester",
    version,
    about = "Prove local webhook handler behavior with signed, mutated, replayed, and duplicate deliveries",
    after_help = "Examples:\n  webhook-security-tester init\n  webhook-security-tester fixtures list --profile github\n  webhook-security-tester test -c webhook-security-tester.toml --only signature --json report.json"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Create an example configuration without overwriting an existing file.
    Init {
        #[arg(long, default_value = "webhook-security-tester.toml")]
        output: PathBuf,
    },
    /// Send the selected conformance scenarios to a local endpoint.
    Test {
        #[arg(short, long, default_value = "webhook-security-tester.toml")]
        config: PathBuf,
        #[arg(long, value_enum)]
        only: Vec<Category>,
        #[arg(long)]
        json: Option<PathBuf>,
        #[arg(long)]
        markdown: Option<PathBuf>,
        #[arg(short, long)]
        quiet: bool,
        #[arg(short, long, conflicts_with = "quiet")]
        verbose: bool,
    },
    /// Inspect built-in scenarios.
    Fixtures {
        #[command(subcommand)]
        command: FixtureCommand,
    },
    /// Explain a scenario and its security significance.
    Explain { id: String },
}
#[derive(Subcommand)]
enum FixtureCommand {
    List {
        #[arg(long, value_enum)]
        profile: Option<Profile>,
    },
}
#[tokio::main]
async fn main() {
    let code = match run().await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Webhook Security Tester error: {e:#}");
            2
        }
    };
    std::process::exit(code)
}
async fn run() -> Result<i32> {
    match Cli::parse().command {
        Command::Init { output } => {
            use std::io::Write;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)
                .with_context(|| {
                    format!(
                        "cannot create {}; existing files are never overwritten",
                        output.display()
                    )
                })?;
            f.write_all(GITHUB_SAMPLE.as_bytes())?;
            println!("Created {}", output.display());
            Ok(0)
        }
        Command::Fixtures {
            command: FixtureCommand::List { profile },
        } => {
            for s in fixture::SCENARIOS {
                if profile.is_none_or(|p| p == s.profile) {
                    println!(
                        "{:<14} {:<10?} {:<12?} {}",
                        s.id, s.category, s.expected, s.description
                    );
                }
            }
            Ok(0)
        }
        Command::Explain { id } => {
            let s = fixture::find(&id).ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown scenario {id}; use `webhook-security-tester fixtures list`"
                )
            })?;
            println!("{} — {}\nProfile: {}\nProvider behavior: {}\nCategory: {:?}\nPurpose and mutation: {}\nExpected: {:?}\nWhy failure matters: {}\nSuggested remediation: {}\nReference: {}",s.id,s.title,s.profile.identifier(),s.profile.protocol_summary(),s.category,s.description,s.expected,fixture::failure_meaning(s),s.remediation,s.reference);
            Ok(0)
        }
        Command::Test {
            config,
            only,
            json,
            markdown,
            quiet,
            verbose,
        } => {
            let config = Config::load(&config)?;
            let only = only.into_iter().collect::<HashSet<_>>();
            let report = runner::run(&config, &only).await?;
            use std::io::IsTerminal;
            let color = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
            print!("{}", report.terminal(quiet, color, verbose));
            if let Some(path) = json {
                fs::write(&path, serde_json::to_vec_pretty(&report)?)
                    .with_context(|| format!("cannot write {}", path.display()))?;
            }
            if let Some(path) = markdown {
                fs::write(&path, report.markdown())
                    .with_context(|| format!("cannot write {}", path.display()))?;
            }
            Ok(report.exit_code(config.observer.require))
        }
    }
}
