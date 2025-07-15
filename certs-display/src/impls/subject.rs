use certs_types::{
    id::{Serial, Ski},
    sans::Sans,
    subject::Subject,
};
use iocraft::{
    AnyElement, Color, FlexDirection, Props, component, element,
    prelude::{Text, View},
};

use crate::impls::{sans::SansView, util::LabeledText};

#[derive(Default, Props)]
pub(crate) struct SubjectViewProps<'a> {
    pub(crate) subject: Option<&'a Subject>,
    pub(crate) sans: Option<&'a Sans>,
    pub(crate) ski: Option<&'a Ski>,
    pub(crate) serial: Option<&'a Serial>,
}

#[component]
pub(crate) fn SubjectView<'a>(props: &SubjectViewProps<'a>) -> impl Into<AnyElement<'a>> {
    let Some(subject) = &props.subject else {
        return element! { View { Text(content: "no subject", color: Color::Red) } };
    };

    element! {
        View(flex_direction: FlexDirection::Column) {
            View {
              Text(content: "subject:", color: Color::Green)
              Text(content: subject.to_string(), color: Color::Green)
            }
            View(flex_direction: FlexDirection::Column, margin_left: 2) {
                SansView(sans: props.sans)
                LabeledText::<Ski>(label: "ski:", content: props.ski)
                LabeledText::<Serial>(label: "serial:", content: props.serial)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::impls::util::render_to_string;

    use super::*;

    #[test]
    fn subject_view() {
        let subject = Subject {
            common_name: Some(Arc::from("cloudflare.com")),
            organization: Some(Arc::from("Cloudflare, Inc.")),
            organization_unit: Some(Arc::from("Cloudflare, Inc.")),
            country: Some(Arc::from("US")),
            state: Some(Arc::from("California")),
        };

        let output = render_to_string(element! { SubjectView(subject: Some(&subject)) });
        println!("{}", output);
        insta::assert_snapshot!(output);
    }
}
