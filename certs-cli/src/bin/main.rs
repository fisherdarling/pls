use certs_cli::args::Cli;

fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    certs_cli::run(args)?;

    Ok(())
}
