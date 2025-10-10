use certs_types::{id::Aki, issuer::Issuer, signature::Signature};
use iocraft::{
    AnyElement, Color, FlexDirection, Props, component, element,
    prelude::{Text, View},
};

use crate::impls::{signature::SignatureView, util::LabeledText};

#[derive(Default, Props)]
pub(crate) struct IssuerViewProps<'a> {
    pub(crate) issuer: Option<&'a Issuer>,
    pub(crate) aki: Option<&'a Aki>,
    pub(crate) signature: Option<&'a Signature>,
}

#[component]
pub(crate) fn IssuerView<'a>(props: &IssuerViewProps<'a>) -> impl Into<AnyElement<'a>> {
    let Some(issuer) = props.issuer else {
        return element! { View { Text(content: "no issuer", color: Color::Red) } };
    };

    element! {
        View(flex_direction: FlexDirection::Column) {
            LabeledText::<Issuer>(label: "issuer:", content: Some(issuer))
            View(flex_direction: FlexDirection::Column, margin_left: 2) {
                LabeledText::<Aki>(label: "aki:", content: props.aki)
                SignatureView(signature: props.signature)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use certs_types::{
        id::Aki, issuer::Issuer, nid::Nid, signature::Signature, subject::Subject, util::Hex,
    };
    use iocraft::element;

    use crate::impls::{issuer::IssuerView, util::render_to_string};

    #[test]
    fn issuer_view() {
        let issuer = Issuer {
            subject: Subject {
                common_name: Some(Arc::from("WE1")),
                organization: Some(Arc::from("Google Trust Services")),
                organization_unit: None,
                country: Some(Arc::from("US")),
                state: None,
            },
        };

        let aki = Aki(Hex::from_hex("9077923567c4ffa8cca9e67bd980797bcc93f938").unwrap());

        let signature = Signature {
            alg: Nid::from_boring(boring::nid::Nid::ECDSA_WITH_SHA256),
            value: Hex::from_hex("3046022100fe06845bc86825b16dcaf4fbafbd2be220f1be979333c062c462cbccf12bc569022100c49de269efeeae0a9a29bbf6528f080f585e3cf4053b8e4452b0746ebbbb645d").unwrap(),
        };

        let output = render_to_string(element! {
            IssuerView(
                issuer: Some(&issuer),
                aki: Some(&aki),
                signature: Some(&signature)
            )
        });
        println!("{}", output);
        // insta::assert_snapshot!(output);
    }
}
