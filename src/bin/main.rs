use pls::{Cli, Command};

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    let args = Cli::parse();

    match args.command() {
        Command::Parse(cert) => cert.run()?,
        Command::Connect(connect) => connect.run().await?,
        Command::NoCommand => {
            let mut clap_command = <Cli as clap::CommandFactory>::command();
            clap_command.print_long_help()?;
        }
    }

    Ok(())
}
