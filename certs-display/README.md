# certs-display

certs-display uses `iocraft` to display certificates and their components.

## Example

iocraft uses a SwiftUI-like syntax for describing print behavior. In this example
we see: Views and flex_directions, gaps, margins, coloring and some helper components.

Components have `#[component]` on them and props must `#[derive(Prop)]` and `impl Default`.
Default impls are kind of difficult, so I tend to use the pattern of
`struct Props { foo: Option<Foo> }` and early return if something's missing.

```rust
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
```

## Testing

To run tests: `cargo test -p certs-display`.

### Adding a new test:

Testing is done using `insta`, a snapshot-testing library. Here's an example of testing the `Sans` struct:

```rust
#[test]
fn test_sans_view() {
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
```

There are four parts to this test:

1. Creating the `Sans` struct we'd like to test.
2. Rendering it to a string.
3. Printing to stdout so Humans/AI can see what it looks like.
4. Asserting the output matches.

If there is any delta, insta will fail with something like:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ Snapshot Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Snapshot file: certs-display/src/impls/snapshots/<some-file>
Snapshot: foo_bar
Source: certs-display/src/impls/foo.rs:62
```

> The name of the snapshot is `foo_bar`.

If the delta looks good, first run `cargo insta pending-snapshots` to get the full paths to the modified snapshots.

Then run `cargo insta accept --snapshot <full-snapshot-path>` to accept it.
