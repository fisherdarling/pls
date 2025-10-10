use std::fmt::Display;

use iocraft::{
    AnyElement, Color, FlexDirection, Props, Weight, component, element,
    prelude::{Text, View},
};

pub(crate) fn labeled_list<'a, T: Display>(label: &'a str, items: &'a [T]) -> AnyElement<'a> {
    element! {
        View(gap: 1) {
            Text(content: label, color: Color::Green)
            View(gap: 1) {
                #(items.iter().map(|item| element!{Text(content: item.to_string(), color: Color::Green)}))
            }
        }
    }.into_any()
}

#[derive(Props)]
pub(crate) struct LabeledTextProps<'a, T: Display + Send + Sync + 'static> {
    pub(crate) label: &'a str,
    pub(crate) content: Option<&'a T>,
}

impl<'a, T: Display + Send + Sync + 'static> Default for LabeledTextProps<'a, T> {
    fn default() -> Self {
        Self {
            label: "",
            content: None,
        }
    }
}

#[component]
pub(crate) fn LabeledText<'a, T: Display + Send + Sync + 'static>(
    props: &mut LabeledTextProps<'a, T>,
) -> impl Into<AnyElement<'a>> {
    let Some(content) = props.content else {
        return element! { View(gap: 1) {
            Text(content: props.label, weight: Weight::Light)
            Text(content: "n/a", weight: Weight::Light)
        }};
    };

    element! {
        View(gap: 1) {
            Text(content: props.label, color: Color::Green)
            Text(content: content.to_string(), color: Color::Green)
        }
    }
}

#[derive(Props)]
pub(crate) struct OwnedLabeledTextProps<T: Display + Send + Sync + 'static> {
    pub(crate) label: String,
    pub(crate) content: Option<T>,
    pub(crate) children: Vec<AnyElement<'static>>,
}

impl<T: Display + Send + Sync + 'static> Default for OwnedLabeledTextProps<T> {
    fn default() -> Self {
        Self {
            label: String::new(),
            content: None,
            children: vec![],
        }
    }
}

#[component]
pub(crate) fn OwnedLabeledText<T: Display + Send + Sync + 'static>(
    props: &mut OwnedLabeledTextProps<T>,
) -> impl Into<AnyElement<'static>> {
    let Some(content) = &props.content else {
        return element! { View(gap: 1) {
            Text(content: props.label.as_str(), weight: Weight::Light)
            Text(content: "n/a", weight: Weight::Light)
        }};
    };

    element! {
        View {
            View(gap: 1) {
                Text(content: props.label.as_str(), color: Color::Green)
                Text(content: content.to_string(), color: Color::Green)
            }
            #(props.children.iter_mut())
        }
    }
}

#[cfg(test)]
pub(crate) fn render_to_string<'a>(element: impl Into<AnyElement<'a>>) -> String {
    use iocraft::ElementExt;

    let mut element = element.into();
    let canvas = element.render(None);
    let mut output = Vec::new();
    canvas.write(&mut output).unwrap();
    String::from_utf8(output).unwrap()
}
