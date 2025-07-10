use certs_types::signature::Signature;
use iocraft::{
    AnyElement, Color, element,
    prelude::{Text, View},
};

use crate::{Config, Repr};

impl Repr for Signature {
    fn text(&self, _config: &Config) -> anyhow::Result<AnyElement<'static>> {
        Ok(element! { View {
            Text(content: "signature:", color: Color::Green)
            View(gap: 1) {
                View {
                    Text(content: "  algorithm: ", color: Color::Green)
                    Text(content: self.alg.long_name())
                }
                View {
                    Text(content: "  value: ", color: Color::Green)
                    Text(content: format!("{:?}", self.value))
                }
            }
        }}.into_any())
    }

    fn json(&self, _config: &Config) -> anyhow::Result<serde_json::Value> {
        let mut obj = serde_json::Map::new();
        
        obj.insert("algorithm".to_string(), serde_json::Value::String(self.alg.long_name().to_string()));
        obj.insert("value".to_string(), serde_json::Value::String(format!("{:?}", self.value)));
        
        Ok(serde_json::Value::Object(obj))
    }
}

#[cfg(test)]
mod tests {
    use certs_types::{util::Hex, nid::Nid};
    use iocraft::ElementExt;
    use serde_json::json;
    use boring::nid::Nid as BoringNid;

    use super::*;

    #[test]
    fn test_signature() {
        let signature = Signature {
            alg: Nid::from_boring(BoringNid::SHA256WITHRSAENCRYPTION),
            value: Hex::from_hex("abcd1234").unwrap(),
        };

        // Test text output
        let mut element = signature.text(&Config::default()).unwrap();
        let canvas = element.render(None);
        let mut output = Vec::new();
        canvas.write(&mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        
        assert!(text.contains("signature:"));
        assert!(text.contains("algorithm:"));
        assert!(text.contains("value: abcd1234"));

        // Test JSON output
        let json = signature.json(&Config::default()).unwrap();
        assert!(json.get("algorithm").is_some());
        assert_eq!(json.get("value").unwrap(), &json!("abcd1234"));
    }
}