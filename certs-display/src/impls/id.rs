use certs_types::id::{Aki, Serial, Ski};
use iocraft::{
    AnyElement, Color, element,
    prelude::{Text, View},
};

use crate::{Config, Repr};

macro_rules! id_repr {
    ($id:ident, $name:literal) => {
        impl Repr for $id {
            fn text(&self, _config: &Config) -> anyhow::Result<AnyElement<'static>> {
                Ok(element! { View {
                    Text(content: $name, color: Color::Green)
                    Text(content: format!("{:?}", self.0))
                }}
                .into_any())
            }

            fn json(&self, _config: &Config) -> anyhow::Result<serde_json::Value> {
                Ok(serde_json::Value::String(format!("{:?}", self.0)))
            }
        }
    };
}

id_repr!(Serial, "serial: ");
id_repr!(Aki, "aki: ");
id_repr!(Ski, "ski: ");

#[cfg(test)]
mod tests {
    use certs_types::util::Hex;
    use iocraft::ElementExt;

    use super::*;

    #[test]
    fn test_ids() {
        let serial = Serial(Hex::from_hex("abcd1234").unwrap());
        let mut element = serial.text(&Config::default()).unwrap();
        let canvas = element.render(None);

        let mut output = Vec::new();
        canvas.write(&mut output).unwrap();

        let text = String::from_utf8(output).unwrap();
        assert_eq!(text, "serial: abcd1234\n");

        let json = serial.json(&Config::default()).unwrap();
        assert_eq!(json, serde_json::Value::String("abcd1234".to_string()));
    }
}
