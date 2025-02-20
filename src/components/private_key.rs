use iocraft::{
    component, element,
    prelude::{Text, View},
    AnyElement, Color, ElementExt, FlexDirection, Props,
};

use crate::{
    commands::Format,
    theme::{HIGHLIGHT_COLOR, TOP_LEVEL_COLOR},
    x509::{SimplePrivateKey, SimplePrivateKeyKind},
};

#[derive(Default, Props)]
pub struct PrivateKeyProps {
    priv_key: SimplePrivateKey,
}

#[component]
pub fn PrivateKeyView(props: &PrivateKeyProps) -> impl Into<AnyElement<'static>> {
    match &props.priv_key.kind {
        SimplePrivateKeyKind::RSA {
            size,
            modulus,
            exponent,
            p,
            q,
            key,
        } => {
            element! {
                View(flex_direction: FlexDirection::Column) {
                    View() {
                        Text(content: "type: ", color: TOP_LEVEL_COLOR)
                        Text(content: "RSA Private Key", color: HIGHLIGHT_COLOR)
                    }
                    View() {
                        Text(content: "size: ", color: TOP_LEVEL_COLOR)
                        Text(content: format!("{}", size), )
                    }
                    View() {
                        Text(content: "exponent: ", color: TOP_LEVEL_COLOR)
                        Text(content: format!("{}", exponent), )
                    }
                    View() {
                        Text(content: "modulus: ", color: TOP_LEVEL_COLOR)
                        Text(content: format!("{}", modulus), )
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
                        Text(content: "key: ", color: TOP_LEVEL_COLOR)
                        Text(content: format!("{}", key), )
                    }
                }
            }
        }
        SimplePrivateKeyKind::DSA {
            size,
            p,
            q,
            g,
            pub_key,
            key,
        } => {
            element! {
                View(flex_direction: FlexDirection::Column) {
                    View() {
                        Text(content: "type: ", color: TOP_LEVEL_COLOR)
                        Text(content: "DSA Private Key", color: HIGHLIGHT_COLOR)
                    }
                    View() {
                        Text(content: "size: ", color: TOP_LEVEL_COLOR)
                        Text(content: format!("{}", size), )
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
                        Text(content: "pub_key: ", color: TOP_LEVEL_COLOR)
                        Text(content: format!("{}", pub_key), )
                    }
                    View() {
                        Text(content: "key: ", color: TOP_LEVEL_COLOR)
                        Text(content: format!("{}", key), )
                    }
                }
            }
        }
        SimplePrivateKeyKind::EC {
            group,
            pub_key,
            key,
        } => {
            let group = group.and_then(|g| g.short_name().ok()).unwrap_or("unknown");

            element! {
                View(flex_direction: FlexDirection::Column) {
                    View() {
                        Text(content: "type: ", color: TOP_LEVEL_COLOR)
                        Text(content: "EC Private Key", color: HIGHLIGHT_COLOR)
                    }
                    View() {
                        Text(content: "group: ", color: TOP_LEVEL_COLOR)
                        Text(content: format!("{}", group), )
                    }
                    View() {
                        Text(content: "pub_key: ", color: TOP_LEVEL_COLOR)
                        Text(content: format!("{}", pub_key), )
                    }
                    View() {
                        Text(content: "key: ", color: TOP_LEVEL_COLOR)
                        Text(content: format!("{}", key), )
                    }
                }
            }
        }
        SimplePrivateKeyKind::Ed25519 { pub_key, key } => {
            element! {
                View(flex_direction: FlexDirection::Column) {
                    View() {
                        Text(content: "type: ", color: TOP_LEVEL_COLOR)
                        Text(content: "Ed25519 Private Key", color: HIGHLIGHT_COLOR)
                    }
                    View() {
                        Text(content: "pub_key: ", color: TOP_LEVEL_COLOR)
                        Text(content: format!("{}", pub_key), )
                    }
                    View() {
                        Text(content: "key: ", color: TOP_LEVEL_COLOR)
                        Text(content: format!("{}", key), )
                    }
                }
            }
        }
        SimplePrivateKeyKind::Ed448 { pub_key, key } => {
            element! {
                View(flex_direction: FlexDirection::Column) {
                    View() {
                        Text(content: "type: ", color: TOP_LEVEL_COLOR)
                        Text(content: "Ed448 Private Key", color: HIGHLIGHT_COLOR)
                    }
                    View() {
                        Text(content: "pub_key: ", color: TOP_LEVEL_COLOR)
                        Text(content: format!("{}", pub_key), )
                    }
                    View() {
                        Text(content: "key: ", color: TOP_LEVEL_COLOR)
                        Text(content: format!("{}", key), )
                    }
                }
            }
        }
    }
}

#[derive(Default, Props)]
pub struct MultiplePrivateKeyViewProps {
    pub priv_keys: Vec<SimplePrivateKey>,
}

#[component]
pub fn MultiplePrivateKeyView(
    props: &MultiplePrivateKeyViewProps,
) -> impl Into<AnyElement<'static>> {
    let keys = props
        .priv_keys
        .iter()
        .cloned()
        .enumerate()
        .map(|(i, priv_key)| {
            element! {
                View(flex_direction: FlexDirection::Column) {
                        Text(content: format!("private key #{}:", i + 1), color: Color::Magenta)
                    PrivateKeyView(priv_key)
                }
            }
        });

    element! {
        View(flex_direction: FlexDirection::Column, gap: 1) {
            #(keys)
        }
    }
}

pub fn print_private_keys(
    priv_keys: Vec<SimplePrivateKey>,
    format: Format,
) -> color_eyre::Result<()> {
    tracing::info!("printing {} keys in {format:?} format", priv_keys.len());
    match format {
        Format::Text => {
            element! {
                View(margin: 1) {
                    MultiplePrivateKeyView(priv_keys)
                }
            }
            .print();
        }
        Format::Json => {
            println!("{}", serde_json::to_string_pretty(&priv_keys)?);
        }
        Format::Pem => {
            for priv_key in priv_keys {
                print!("{}", priv_key.pem);
            }
        }
    }

    Ok(())
}
