use certs_types::signature::Signature;
use iocraft::{
    AnyElement, Color, FlexDirection, Props, component, element,
    prelude::{Text, View},
};

use crate::impls::util::OwnedLabeledText;

#[derive(Default, Props)]
pub(crate) struct SignatureViewProps<'a> {
    pub(crate) signature: Option<&'a Signature>,
}

#[component]
pub(crate) fn SignatureView<'a>(props: &SignatureViewProps<'a>) -> impl Into<AnyElement<'a>> {
    let Some(signature) = props.signature else {
        return element! { View { Text(content: "no signature", color: Color::Red) } }.into_any();
    };

    let signature_value = format!("{:?}", signature.value);

    element! {
        View(flex_direction: FlexDirection::Column) {
            OwnedLabeledText::<&'static str>(label: "signature:", content: Some(signature.alg.long_name()))
            View(width: 72, margin_left: 2) {
                Text(content: signature_value, )
            }
        }
    }
    .into_any()
}

#[cfg(test)]
mod tests {
    use certs_types::cert::Cert;

    use crate::impls::util::render_to_string;

    use super::*;

    #[test]
    fn test_signature_view() {
        let cert = Cert::from_pem(include_bytes!(
            "../../../test-data/certs/cloudflare.com.pem"
        ))
        .unwrap();

        let signature = cert.signature;
        let output = render_to_string(element! { SignatureView(signature: Some(&signature)) });
        println!("{}", output);

        // insta::assert_snapshot!(view.to_string());
    }
}
