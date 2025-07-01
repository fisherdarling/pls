use crate::context::Ctx;

pub mod args;
pub mod context;

pub fn run(args: args::Cli) -> anyhow::Result<()> {
    let ctx = Ctx::from_args(&args)?;

    match args.command {
        args::Command::Scan(args) => args.run(&ctx)?,
    }

    Ok(())
}

pub fn init_tracing(args: &args::Cli) {
    let subscriber = tracing_subscriber::fmt::Subscriber::builder()
        .with_max_level(args.verbose.filter())
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
}
