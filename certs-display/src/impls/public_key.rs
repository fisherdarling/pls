use certs_types::key::PublicKey;
use iocraft::{
    AnyElement, Color, element,
    prelude::{Text, View},
};

use crate::{Config, Repr};

impl Repr for PublicKey {
    fn text(&self, _config: &Config) -> anyhow::Result<AnyElement<'static>> {
        match self {
            PublicKey::Rsa { n, e } => {
                // Convert to bytes to get length
                let n_bytes: bytes::Bytes = n.clone().into();
                let key_size = n_bytes.len() * 8; // Estimate key size from modulus length
                Ok(element! { View {
                    Text(content: "public_key:", color: Color::Green)
                    View(gap: 1) {
                        View {
                            Text(content: "  type: ", color: Color::Green)
                            Text(content: "RSA")
                        }
                        View {
                            Text(content: "  size: ", color: Color::Green)
                            Text(content: format!("{} bits", key_size))
                        }
                        View {
                            Text(content: "  modulus: ", color: Color::Green)
                            Text(content: format!("{:?}", n))
                        }
                        View {
                            Text(content: "  exponent: ", color: Color::Green)
                            Text(content: format!("{:?}", e))
                        }
                    }
                }}.into_any())
            }
            PublicKey::Ec { curve, point } => {
                Ok(element! { View {
                    Text(content: "public_key:", color: Color::Green)
                    View(gap: 1) {
                        View {
                            Text(content: "  type: ", color: Color::Green)
                            Text(content: "EC")
                        }
                        View {
                            Text(content: "  curve: ", color: Color::Green)
                            Text(content: format!("{:?}", curve))
                        }
                        View {
                            Text(content: "  point: ", color: Color::Green)
                            Text(content: format!("{:?}", point))
                        }
                    }
                }}.into_any())
            }
            PublicKey::Ed25519 { key } => {
                Ok(element! { View {
                    Text(content: "public_key:", color: Color::Green)
                    View(gap: 1) {
                        View {
                            Text(content: "  type: ", color: Color::Green)
                            Text(content: "Ed25519")
                        }
                        View {
                            Text(content: "  key: ", color: Color::Green)
                            Text(content: format!("{:?}", key))
                        }
                    }
                }}.into_any())
            }
        }
    }

    fn json(&self, _config: &Config) -> anyhow::Result<serde_json::Value> {
        match self {
            PublicKey::Rsa { n, e } => {
                // Convert to bytes to get length
                let n_bytes: bytes::Bytes = n.clone().into();
                let key_size = n_bytes.len() * 8; // Estimate key size from modulus length
                let mut obj = serde_json::Map::new();
                obj.insert("type".to_string(), serde_json::Value::String("rsa".to_string()));
                obj.insert("size".to_string(), serde_json::Value::Number(key_size.into()));
                obj.insert("modulus".to_string(), serde_json::Value::String(format!("{:?}", n)));
                obj.insert("exponent".to_string(), serde_json::Value::String(format!("{:?}", e)));
                Ok(serde_json::Value::Object(obj))
            }
            PublicKey::Ec { curve, point } => {
                let mut obj = serde_json::Map::new();
                obj.insert("type".to_string(), serde_json::Value::String("ec".to_string()));
                obj.insert("curve".to_string(), serde_json::Value::String(format!("{:?}", curve)));
                obj.insert("point".to_string(), serde_json::Value::String(format!("{:?}", point)));
                Ok(serde_json::Value::Object(obj))
            }
            PublicKey::Ed25519 { key } => {
                let mut obj = serde_json::Map::new();
                obj.insert("type".to_string(), serde_json::Value::String("ed25519".to_string()));
                obj.insert("key".to_string(), serde_json::Value::String(format!("{:?}", key)));
                Ok(serde_json::Value::Object(obj))
            }
        }
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
    fn test_rsa_public_key() {
        let rsa_key = PublicKey::Rsa {
            n: Hex::from_hex("abcd1234").unwrap(),
            e: Hex::from_hex("010001").unwrap(),
        };

        // Test text output
        let mut element = rsa_key.text(&Config::default()).unwrap();
        let canvas = element.render(None);
        let mut output = Vec::new();
        canvas.write(&mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        
        assert!(text.contains("public_key:"));
        assert!(text.contains("type: RSA"));
        assert!(text.contains("size: 32 bits"));
        assert!(text.contains("modulus: abcd1234"));
        assert!(text.contains("exponent: 010001"));

        // Test JSON output
        let json = rsa_key.json(&Config::default()).unwrap();
        assert_eq!(json.get("type").unwrap(), &json!("rsa"));
        assert_eq!(json.get("size").unwrap(), &json!(32));
        assert_eq!(json.get("modulus").unwrap(), &json!("abcd1234"));
        assert_eq!(json.get("exponent").unwrap(), &json!("010001"));
    }

    #[test]
    fn test_ec_public_key() {
        let ec_key = PublicKey::Ec {
            curve: Nid::from_boring(BoringNid::X9_62_PRIME256V1),
            point: Hex::from_hex("abcd1234").unwrap(),
        };

        // Test text output
        let mut element = ec_key.text(&Config::default()).unwrap();
        let canvas = element.render(None);
        let mut output = Vec::new();
        canvas.write(&mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        
        assert!(text.contains("public_key:"));
        assert!(text.contains("type: EC"));
        assert!(text.contains("curve:"));
        assert!(text.contains("point: abcd1234"));

        // Test JSON output
        let json = ec_key.json(&Config::default()).unwrap();
        assert_eq!(json.get("type").unwrap(), &json!("ec"));
        assert!(json.get("curve").is_some());
        assert_eq!(json.get("point").unwrap(), &json!("abcd1234"));
    }

    #[test]
    fn test_ed25519_public_key() {
        let ed25519_key = PublicKey::Ed25519 {
            key: Hex::from_hex("abcd1234").unwrap(),
        };

        // Test text output
        let mut element = ed25519_key.text(&Config::default()).unwrap();
        let canvas = element.render(None);
        let mut output = Vec::new();
        canvas.write(&mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        
        assert!(text.contains("public_key:"));
        assert!(text.contains("type: Ed25519"));
        assert!(text.contains("key: abcd1234"));

        // Test JSON output
        let json = ed25519_key.json(&Config::default()).unwrap();
        assert_eq!(json.get("type").unwrap(), &json!("ed25519"));
        assert_eq!(json.get("key").unwrap(), &json!("abcd1234"));
    }
}