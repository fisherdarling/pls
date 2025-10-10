use clap_verbosity_flag::tracing::LevelFilter;

use crate::context::Ctx;

pub mod args;
pub mod context;

pub fn run(args: args::Cli) -> anyhow::Result<()> {
    init_tracing(&args);
    let ctx = Ctx::from_args(&args)?;

    match args.command {
        args::Command::Scan(args) => args.run(&ctx)?,
        args::Command::Parse(args) => args.run(&ctx)?,
    }

    Ok(())
}

pub fn init_tracing(args: &args::Cli) {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(LevelFilter::WARN)
        .json()
        .flatten_event(true)
        .with_ansi(false)
        .finish();

    if let Err(err) = tracing::subscriber::set_global_default(subscriber) {
        eprintln!("failed to install tracing subscriber: {err}");
    }
}
