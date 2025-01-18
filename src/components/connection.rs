use iocraft::{
    component, element,
    prelude::{Text, TextDecoration, View},
    AnyElement, Color, ElementExt, FlexDirection, Props,
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
                #(if props.tls.valid {
                    element! {
                        Text(content: "✅ connection secure", color: Color::Green)
                    }
                } else {
                    element! {
                        Text(content: format!("🚨 connection insecure: {}", props.tls.verify_result.clone().unwrap_or_default()), color: Color::Red, decoration: TextDecoration::Underline)
                    }
                })
                View(gap: 1) {
                    Text(content: "curve:")
                    Text(content: props.tls.curve.clone(), color: HIGHLIGHT_COLOR)
                }
                Text(content: format!("valid: {}", props.tls.valid))
                View(gap: 1) {
                    Text(content: format!("dns: {:.2?}", props.tls.time.dns))
                    Text(content: format!("connect: {:.2?}", props.tls.time.connect))
                    Text(content: format!("secure: {:.2?}", props.tls.time.tls))
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
