use iocraft::{AnyElement, FlexDirection, Props, component, element, prelude::View};

use certs_types::sans::Sans;

use crate::impls::util::labeled_list;

#[derive(Default, Props)]
pub(crate) struct SansViewProps<'a> {
    pub(crate) sans: Option<&'a Sans>,
}

#[component]
pub(crate) fn SansView<'a>(props: &SansViewProps<'a>) -> impl Into<AnyElement<'a>> {
    let mut parts = Vec::new();

    if let Some(sans) = &props.sans {
        if !sans.dns.is_empty() {
            parts.push(labeled_list("dns:", &sans.dns));
        }

        if !sans.ip.is_empty() {
            parts.push(labeled_list("ip:", &sans.ip));
        }

        if !sans.email.is_empty() {
            parts.push(labeled_list("email:", &sans.email));
        }

        if !sans.uri.is_empty() {
            parts.push(labeled_list("uri:", &sans.uri));
        }
    }

    element! {
        View(flex_direction: FlexDirection::Column) {
            #(parts)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::impls::util::render_to_string;

    use super::*;

    #[test]
    fn sans_view() {
        let sans = Sans {
            dns: Arc::new(["example.com".to_string()]),
            ip: Arc::new(["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()]),
            email: Arc::new(["test@example.com".to_string()]),
            uri: Arc::new(["https://example.com".to_string()]),
        };

        let output = render_to_string(element! { SansView(sans: Some(&sans)) });
        println!("{}", output);
        insta::assert_snapshot!(output);
    }
}
