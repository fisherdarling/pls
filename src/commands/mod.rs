use std::io::IsTerminal as _;

pub mod connect;
pub mod parse;

#[allow(async_fn_in_trait)]
pub trait CommandExt {
    async fn run(self, format: Format) -> color_eyre::Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
}

impl Format {
    pub fn from_args(text: bool, json: bool) -> Self {
        let print_json = json || (!text && !std::io::stdout().is_terminal());

        if print_json {
            Self::Json
        } else {
            Self::Text
        }
    }
}
