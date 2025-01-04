use iocraft::prelude::*;
use teal::{Cli, Command};

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let args = Cli::parse();
    println!("{args:?}");

    match args.command() {
        Command::Parse(cert) => cert.run()?,
    }

    element! {
        View(
            border_style: BorderStyle::Round,
            border_color: Color::Blue,
        ) {
            Text(content: "Hello, world!")
        }
    }
    .print();

    Ok(())
}
