use std::io::IsTerminal;

use pls::Cli;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    let args = Cli::parse();

    init_tracing(&args)?;
    tracing::debug!("args: {args:?}");

    let format = args.format();
    args.command().run(format).await?;

    Ok(())
}

fn init_tracing(args: &Cli) -> color_eyre::Result<()> {
    let enable_ansi = std::io::stderr().is_terminal();

    let subscriber = tracing_subscriber::fmt()
        .with_max_level(args.verbose.tracing_level_filter())
        .with_ansi(enable_ansi)
        .with_writer(std::io::stderr)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;
    Ok(())
}
