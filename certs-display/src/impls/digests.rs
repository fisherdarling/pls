use certs_types::id::Digests;
use iocraft::{
    AnyElement, Color, element,
    prelude::{Text, View},
};

use crate::{Config, Repr};

impl Repr for Digests {
    fn text(&self, _config: &Config) -> anyhow::Result<AnyElement<'static>> {
        Ok(element! { View {
            Text(content: "digests:", color: Color::Green)
            View(gap: 1) {
                View {
                    Text(content: "  md5: ", color: Color::Green)
                    Text(content: format!("{:?}", self.md5))
                }
                View {
                    Text(content: "  sha1: ", color: Color::Green)
                    Text(content: format!("{:?}", self.sha1))
                }
                View {
                    Text(content: "  sha256: ", color: Color::Green)
                    Text(content: format!("{:?}", self.sha256))
                }
            }
        }}.into_any())
    }

    fn json(&self, _config: &Config) -> anyhow::Result<serde_json::Value> {
        let mut obj = serde_json::Map::new();
        
        obj.insert("md5".to_string(), serde_json::Value::String(format!("{:?}", self.md5)));
        obj.insert("sha1".to_string(), serde_json::Value::String(format!("{:?}", self.sha1)));
        obj.insert("sha256".to_string(), serde_json::Value::String(format!("{:?}", self.sha256)));
        
        Ok(serde_json::Value::Object(obj))
    }
}

#[cfg(test)]
mod tests {
    use certs_types::util::Hex;
    use iocraft::ElementExt;
    use serde_json::json;

    use super::*;

    #[test]
    fn test_digests() {
        let digests = Digests {
            md5: Hex::from_hex("abcd1234").unwrap(),
            sha1: Hex::from_hex("def567890abcdef0").unwrap(),
            sha256: Hex::from_hex("1234567890abcdef1234567890abcdef12345678").unwrap(),
        };

        // Test text output
        let mut element = digests.text(&Config::default()).unwrap();
        let canvas = element.render(None);
        let mut output = Vec::new();
        canvas.write(&mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        
        assert!(text.contains("digests:"));
        assert!(text.contains("md5: abcd1234"));
        assert!(text.contains("sha1: def567890abcdef0"));
        assert!(text.contains("sha256: 1234567890abcdef1234567890abcdef12345678"));

        // Test JSON output
        let json = digests.json(&Config::default()).unwrap();
        let expected = json!({
            "md5": "abcd1234",
            "sha1": "def567890abcdef0",
            "sha256": "1234567890abcdef1234567890abcdef12345678"
        });
        assert_eq!(json, expected);
    }
}