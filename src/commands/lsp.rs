use clap::Parser;
use tower_lsp_server::jsonrpc::Result;
use tower_lsp_server::lsp_types::*;
use tower_lsp_server::{Client, LanguageServer, LspService, Server};

use super::{CommandExt, Format};

#[derive(Default, Clone, Debug, Parser)]
pub struct Lsp {}

impl CommandExt for Lsp {
    async fn run(self, _format: Format) -> color_eyre::Result<()> {
        let stdin = tokio::io::stdin();
        let stdout = tokio::io::stdout();

        let (service, socket) = LspService::new(|client| Backend { client });
        Server::new(stdin, stdout, socket).serve(service).await;

        Ok(())
    }
}

#[derive(Debug)]
struct Backend {
    client: Client,
}

#[tower_lsp_server::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult::default())
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "server initialized!")
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }
}
