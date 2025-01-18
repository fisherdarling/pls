use iocraft::{
    component, element,
    prelude::{Text, View},
    AnyElement, ElementExt, FlexDirection, Props,
};
use serde::Serialize;

use crate::{
    commands::Format,
    components::x509::{MultipleCertView, SurroundText},
    connection::Connection,
    theme::{HIGHLIGHT_COLOR, TOP_LEVEL_COLOR},
    x509::cert::SimpleCert,
};

#[derive(Default, Props)]
pub struct TlsConnectionProps {
    pub tls: Connection,
}

#[component]
pub fn TlsConnectionView(props: &TlsConnectionProps) -> impl Into<AnyElement<'static>> {
    element! {
        View(flex_direction: FlexDirection::Column) {
            View(gap: 1) {
                Text(content: format!("{}:", props.tls.version), color: TOP_LEVEL_COLOR)
                View() {
                    SurroundText(left: "(", text: format!("{:?}", props.tls.transport), right: ")")
                }
            }
            View(flex_direction: FlexDirection::Column, left: 4) {
                View(gap: 1) {
                    Text(content: "curve:")
                    Text(content: props.tls.curve.clone(), color: HIGHLIGHT_COLOR)
                }
                View(flex_direction: FlexDirection::Row, gap: 1) {
                    View(gap: 1) {
                        Text(content: "dns:")
                        Text(content: format!("{:.2?},", props.tls.time.dns))
                    }
                    View(gap: 1) {
                        Text(content: "connect:")
                        Text(content: format!("{:.2?},", props.tls.time.connect))
                    }
                    View(gap: 1) {
                        Text(content: "secure:")
                        Text(content: format!("{:.2?},", props.tls.time.tls))
                    }
                }
            }
        }

    }
}

#[derive(Default, Debug, Serialize)]
pub struct ConnectionWithCerts {
    pub tls: Connection,
    pub certs: Vec<SimpleCert>,
}

pub fn print_tls_connection_with_certs(
    connection: ConnectionWithCerts,
    format: Format,
) -> color_eyre::Result<()> {
    match format {
        Format::Text => {
            element! {
                View(flex_direction: FlexDirection::Column, gap: 1) {
                    TlsConnectionView(tls: connection.tls)
                    View(flex_direction: FlexDirection::Column) {
                        Text(content: if connection.certs.len() > 1 {"certs:"} else {"cert:"}, color: TOP_LEVEL_COLOR)
                        View(left: 4) {
                            MultipleCertView(certs: connection.certs)
                        }
                    }
                }
            }
            .print();
        }
        Format::Json => {
            println!("{}", serde_json::to_string_pretty(&connection)?);
        }
    }

    Ok(())
}
