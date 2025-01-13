use pls::{Cli, Command};

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    let args = Cli::parse();

    match args.command() {
        Command::Parse(cert) => cert.run()?,
    }

    Ok(())
}
