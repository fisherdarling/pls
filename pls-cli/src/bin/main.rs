use pls_cli::args::Cli;

fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    pls_cli::run(args)?;

    Ok(())
}
