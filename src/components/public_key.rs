use iocraft::{
    component, element,
    prelude::{Text, View},
    AnyElement, Color, ElementExt, FlexDirection, Props,
};

use crate::{
    commands::Format,
    theme::{HIGHLIGHT_COLOR, TOP_LEVEL_COLOR},
    x509::{SimplePublicKey, SimplePublicKeyKind},
};

#[derive(Default, Props)]
pub struct PublicKeyProps {
    pub_key: SimplePublicKey,
}

#[component]
pub fn PublicKeyView(props: &PublicKeyProps) -> impl Into<AnyElement<'static>> {
    tracing::info!("public key: {:?}", props.pub_key);

    match &props.pub_key.kind {
        SimplePublicKeyKind::RSA {
            size,
            modulus,
            exponent,
        } => {
            element! {
                View(flex_direction: FlexDirection::Column) {
                    View() {
                        Text(content: "type: ", color: TOP_LEVEL_COLOR)
                        Text(content: "RSA Public Key", color: HIGHLIGHT_COLOR)
                    }
                    View() {
                        Text(content: "size: ", color: TOP_LEVEL_COLOR)
                        Text(content: format!("{} bits", size), )
                    }
                    View() {
                        Text(content: "exponent: ", color: TOP_LEVEL_COLOR)
                        Text(content: format!("{}", exponent), )
                    }
                    View() {
                        Text(content: "modulus: ", color: TOP_LEVEL_COLOR)
                        Text(content: format!("{}", modulus), )
                    }
                }
            }
        }
        SimplePublicKeyKind::DSA { size, p, q, g, key } => {
            element! {
                View(flex_direction: FlexDirection::Column) {
                    View() {
                        Text(content: "type: ", color: TOP_LEVEL_COLOR)
                        Text(content: "DSA Public Key", color: HIGHLIGHT_COLOR)
                    }
                    View() {
                        Text(content: "size: ", color: TOP_LEVEL_COLOR)
                        Text(content: format!("{} bits", size), )
                    }
                    View() {
                        Text(content: "p: ", color: TOP_LEVEL_COLOR)
                        Text(content: format!("{}", p), )
                    }
                    View() {
                        Text(content: "q: ", color: TOP_LEVEL_COLOR)
                        Text(content: format!("{}", q), )
                    }
                    View() {
                        Text(content: "g: ", color: TOP_LEVEL_COLOR)
                        Text(content: format!("{}", g), )
                    }
                    View() {
                        Text(content: "key: ", color: TOP_LEVEL_COLOR)
                        Text(content: format!("{}", key), )
                    }
                }
            }
        }
        SimplePublicKeyKind::EC { group, key } => {
            let group = group.and_then(|g| g.short_name().ok()).unwrap_or("unknown");

            element! {
                View(flex_direction: FlexDirection::Column) {
                    View() {
                        Text(content: "type: ", color: TOP_LEVEL_COLOR)
                        Text(content: "EC Public Key", color: HIGHLIGHT_COLOR)
                    }
                    View() {
                        Text(content: "group: ", color: TOP_LEVEL_COLOR)
                        Text(content: format!("{}", group), )
                    }
                    View() {
                        Text(content: "pub_key: ", color: TOP_LEVEL_COLOR)
                        Text(content: format!("{}", key), )
                    }
                }
            }
        }
        SimplePublicKeyKind::Ed25519 { pub_key } => {
            element! {
                View(flex_direction: FlexDirection::Column) {
                    View() {
                        Text(content: "type: ", color: TOP_LEVEL_COLOR)
                        Text(content: "Ed25519 Public Key", color: HIGHLIGHT_COLOR)
                    }
                    View() {
                        Text(content: "pub_key: ", color: TOP_LEVEL_COLOR)
                        Text(content: format!("{}", pub_key), )
                    }
                }
            }
        }
        SimplePublicKeyKind::Ed448 { pub_key } => {
            element! {
                View(flex_direction: FlexDirection::Column) {
                    View() {
                        Text(content: "type: ", color: TOP_LEVEL_COLOR)
                        Text(content: "Ed448 Public Key", color: HIGHLIGHT_COLOR)
                    }
                    View() {
                        Text(content: "pub_key: ", color: TOP_LEVEL_COLOR)
                        Text(content: format!("{}", pub_key), )
                    }
                }
            }
        }
    }
}

#[derive(Default, Props)]
pub struct MultiplePublicKeyViewProps {
    pub pub_keys: Vec<SimplePublicKey>,
}

#[component]
pub fn MultiplePublicKeyView(props: &MultiplePublicKeyViewProps) -> impl Into<AnyElement<'static>> {
    tracing::info!("public keys: {:?}", props.pub_keys);

    element!(
        View(gap: 1) {
            #(props.pub_keys.iter().cloned().enumerate().map(|(i, pub_key)| element! {
                View(flex_direction: FlexDirection::Column) {
                    #((props.pub_keys.len() > 1).then(|| element! {
                        Text(content: format!("public key #{}:", i + 1), color: Color::Magenta)
                    }))
                    PublicKeyView(pub_key)
                }
            }))
        }
    )
}

pub fn print_public_keys(pub_keys: Vec<SimplePublicKey>, format: Format) -> color_eyre::Result<()> {
    tracing::info!(
        "printing {} public keys in {format:?} format",
        pub_keys.len()
    );
    match format {
        Format::Text => {
            element! {
                View(margin: 1) {
                    MultiplePublicKeyView(pub_keys)
                }
            }
            .print();
        }
        Format::Json => {
            println!("{}", serde_json::to_string_pretty(&pub_keys)?);
        }
        Format::Pem => {
            for pub_key in pub_keys {
                print!("{}", pub_key.pem);
            }
        }
    }

    Ok(())
}
