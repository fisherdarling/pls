use iocraft::{
    component, element,
    prelude::{Text, View},
    AnyElement, Color, ElementExt, FlexDirection, Props,
};

use crate::{
    commands::Format,
    components::x509::{PublicKeyView, SignatureView, SubjectView},
    x509::SimpleCsr,
};

#[derive(Default, Props)]
pub struct CsrProps {
    csr: SimpleCsr,
}

#[component]
pub fn CsrView(props: &CsrProps) -> impl Into<AnyElement<'static>> {
    element! {
        View(flex_direction: FlexDirection::Column) {
            SubjectView(subject: props.csr.subject.clone(), serial: None)
            PublicKeyView(public_key: props.csr.public_key.clone())
            SignatureView(signature: props.csr.signature.clone(), top_level: true)
        }
    }
}

#[derive(Default, Props)]
pub struct MultipleCsrViewProps {
    pub csrs: Vec<SimpleCsr>,
}

#[component]
pub fn MultipleCsrView(props: &MultipleCsrViewProps) -> impl Into<AnyElement<'static>> {
    element! {
        View(flex_direction: FlexDirection::Column, gap: 1) {
            #(props.csrs.iter().cloned().enumerate().map(|(i, csr)| element!(
                View(flex_direction: FlexDirection::Column) {
                    Text(content: format!("csr #{}:", i + 1), color: Color::Magenta)
                    CsrView(csr)
                }
            )))
        }
    }
}

pub fn print_csrs(csrs: Vec<SimpleCsr>, format: Format) -> color_eyre::Result<()> {
    tracing::info!("printing {} csrs in {format:?} format", csrs.len());
    match format {
        Format::Text => {
            element! {
                View(margin: 1) {
                    MultipleCsrView(csrs)
                }
            }
            .print();
        }
        Format::Json => {
            println!("{}", serde_json::to_string_pretty(&csrs)?);
        }
        Format::Pem => {
            for csr in csrs {
                print!("{}", csr.pem);
            }
        }
    }

    Ok(())
}
