use iocraft::{
    component, element,
    prelude::{Text, View},
    AnyElement, Color, ElementExt, FlexDirection, Props,
};
use serde::Serialize;

use crate::{
    commands::Format,
    components::x509::{MultipleCertView, SurroundText, TOP_LEVEL_COLOR},
    connection::Connection,
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
                Text(content: "connection:", color: TOP_LEVEL_COLOR)
                Text(content: props.tls.version.clone())
                View() {
                    SurroundText(left: "(", text: format!("{:?}", props.tls.transport), right: ")")
                }
            }
            View(flex_direction: FlexDirection::Column, left: 4) {
                View(gap: 1) {
                    Text(content: "curve:")
                    Text(content: props.tls.curve.clone(), color: Color::Green)
                }
                View() {
                    Text(content: format!("connected in {:.2?}", props.tls.time_connect))
                    Text(content: ", ")
                    Text(content: format!("secured in {:.2?}", props.tls.time_tls))
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
                    MultipleCertView(certs: connection.certs)
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
