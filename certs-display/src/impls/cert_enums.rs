use certs_types::cert::{CertUsage, CertDepth, CertClassification, BasicConstraints};
use iocraft::{
    AnyElement, Color, element,
    prelude::{Text, View},
};

use crate::{Config, Repr};

impl Repr for CertUsage {
    fn text(&self, _config: &Config) -> anyhow::Result<AnyElement<'static>> {
        let usage_text = match self {
            CertUsage::Client => "Client",
            CertUsage::Server => "Server",
            CertUsage::ClientAndServer => "Client and Server",
            CertUsage::CA => "Certificate Authority",
            CertUsage::Unknown => "Unknown",
        };

        Ok(element! { View {
            Text(content: "usage: ", color: Color::Green)
            Text(content: usage_text)
        }}.into_any())
    }

    fn json(&self, _config: &Config) -> anyhow::Result<serde_json::Value> {
        let usage_str = match self {
            CertUsage::Client => "client",
            CertUsage::Server => "server",
            CertUsage::ClientAndServer => "client_and_server",
            CertUsage::CA => "ca",
            CertUsage::Unknown => "unknown",
        };

        Ok(serde_json::Value::String(usage_str.to_string()))
    }
}

impl Repr for CertDepth {
    fn text(&self, _config: &Config) -> anyhow::Result<AnyElement<'static>> {
        let depth_text = match self {
            CertDepth::Leaf => "Leaf",
            CertDepth::Intermediate => "Intermediate",
            CertDepth::Root => "Root",
        };

        Ok(element! { View {
            Text(content: "depth: ", color: Color::Green)
            Text(content: depth_text)
        }}.into_any())
    }

    fn json(&self, _config: &Config) -> anyhow::Result<serde_json::Value> {
        let depth_str = match self {
            CertDepth::Leaf => "leaf",
            CertDepth::Intermediate => "intermediate",
            CertDepth::Root => "root",
        };

        Ok(serde_json::Value::String(depth_str.to_string()))
    }
}

impl Repr for CertClassification {
    fn text(&self, _config: &Config) -> anyhow::Result<AnyElement<'static>> {
        Ok(element! { View {
            Text(content: "classification:", color: Color::Green)
            View(gap: 1) {
                View {
                    Text(content: "  is_ca: ", color: Color::Green)
                    Text(content: if self.is_ca { "true" } else { "false" })
                }
                View {
                    Text(content: "  authenticates: ", color: Color::Green)
                    Text(content: match self.authenticates {
                        CertUsage::Client => "Client",
                        CertUsage::Server => "Server",
                        CertUsage::ClientAndServer => "Client and Server",
                        CertUsage::CA => "Certificate Authority",
                        CertUsage::Unknown => "Unknown",
                    })
                }
                View {
                    Text(content: "  depth: ", color: Color::Green)
                    Text(content: match self.depth {
                        CertDepth::Leaf => "Leaf",
                        CertDepth::Intermediate => "Intermediate",
                        CertDepth::Root => "Root",
                    })
                }
            }
        }}.into_any())
    }

    fn json(&self, _config: &Config) -> anyhow::Result<serde_json::Value> {
        let mut obj = serde_json::Map::new();
        
        obj.insert("is_ca".to_string(), serde_json::Value::Bool(self.is_ca));
        
        let auth_str = match self.authenticates {
            CertUsage::Client => "client",
            CertUsage::Server => "server",
            CertUsage::ClientAndServer => "client_and_server",
            CertUsage::CA => "ca",
            CertUsage::Unknown => "unknown",
        };
        obj.insert("authenticates".to_string(), serde_json::Value::String(auth_str.to_string()));
        
        let depth_str = match self.depth {
            CertDepth::Leaf => "leaf",
            CertDepth::Intermediate => "intermediate",
            CertDepth::Root => "root",
        };
        obj.insert("depth".to_string(), serde_json::Value::String(depth_str.to_string()));
        
        Ok(serde_json::Value::Object(obj))
    }
}

impl Repr for BasicConstraints {
    fn text(&self, _config: &Config) -> anyhow::Result<AnyElement<'static>> {
        let mut components = Vec::new();
        
        components.push(element! { View {
            Text(content: "  critical: ", color: Color::Green)
            Text(content: if self.critical { "true" } else { "false" })
        }});
        
        components.push(element! { View {
            Text(content: "  is_ca: ", color: Color::Green)
            Text(content: if self.is_ca { "true" } else { "false" })
        }});
        
        if let Some(max_path_length) = self.max_path_length {
            components.push(element! { View {
                Text(content: "  max_path_length: ", color: Color::Green)
                Text(content: max_path_length.to_string())
            }});
        }

        Ok(element! { View {
            Text(content: "basic_constraints:", color: Color::Green)
            View(gap: 1) {
                #(components)
            }
        }}.into_any())
    }

    fn json(&self, _config: &Config) -> anyhow::Result<serde_json::Value> {
        let mut obj = serde_json::Map::new();
        
        obj.insert("critical".to_string(), serde_json::Value::Bool(self.critical));
        obj.insert("is_ca".to_string(), serde_json::Value::Bool(self.is_ca));
        
        if let Some(max_path_length) = self.max_path_length {
            obj.insert("max_path_length".to_string(), serde_json::Value::Number(max_path_length.into()));
        }
        
        Ok(serde_json::Value::Object(obj))
    }
}

#[cfg(test)]
mod tests {
    use iocraft::ElementExt;
    use serde_json::json;

    use super::*;

    #[test]
    fn test_cert_usage_variants() {
        let usage_client = CertUsage::Client;
        let usage_server = CertUsage::Server;
        let usage_both = CertUsage::ClientAndServer;
        let usage_ca = CertUsage::CA;
        let usage_unknown = CertUsage::Unknown;

        // Test text output
        let mut element = usage_client.text(&Config::default()).unwrap();
        let canvas = element.render(None);
        let mut output = Vec::new();
        canvas.write(&mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("usage: Client"));

        let mut element = usage_server.text(&Config::default()).unwrap();
        let canvas = element.render(None);
        let mut output = Vec::new();
        canvas.write(&mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("usage: Server"));

        let mut element = usage_both.text(&Config::default()).unwrap();
        let canvas = element.render(None);
        let mut output = Vec::new();
        canvas.write(&mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("usage: Client and Server"));

        let mut element = usage_ca.text(&Config::default()).unwrap();
        let canvas = element.render(None);
        let mut output = Vec::new();
        canvas.write(&mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("usage: Certificate Authority"));

        let mut element = usage_unknown.text(&Config::default()).unwrap();
        let canvas = element.render(None);
        let mut output = Vec::new();
        canvas.write(&mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("usage: Unknown"));

        // Test JSON output
        assert_eq!(usage_client.json(&Config::default()).unwrap(), json!("client"));
        assert_eq!(usage_server.json(&Config::default()).unwrap(), json!("server"));
        assert_eq!(usage_both.json(&Config::default()).unwrap(), json!("client_and_server"));
        assert_eq!(usage_ca.json(&Config::default()).unwrap(), json!("ca"));
        assert_eq!(usage_unknown.json(&Config::default()).unwrap(), json!("unknown"));
    }

    #[test]
    fn test_cert_depth_variants() {
        let depth_leaf = CertDepth::Leaf;
        let depth_intermediate = CertDepth::Intermediate;
        let depth_root = CertDepth::Root;

        // Test text output
        let mut element = depth_leaf.text(&Config::default()).unwrap();
        let canvas = element.render(None);
        let mut output = Vec::new();
        canvas.write(&mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("depth: Leaf"));

        let mut element = depth_intermediate.text(&Config::default()).unwrap();
        let canvas = element.render(None);
        let mut output = Vec::new();
        canvas.write(&mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("depth: Intermediate"));

        let mut element = depth_root.text(&Config::default()).unwrap();
        let canvas = element.render(None);
        let mut output = Vec::new();
        canvas.write(&mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("depth: Root"));

        // Test JSON output
        assert_eq!(depth_leaf.json(&Config::default()).unwrap(), json!("leaf"));
        assert_eq!(depth_intermediate.json(&Config::default()).unwrap(), json!("intermediate"));
        assert_eq!(depth_root.json(&Config::default()).unwrap(), json!("root"));
    }

    #[test]
    fn test_cert_classification() {
        let classification = CertClassification {
            is_ca: true,
            authenticates: CertUsage::CA,
            depth: CertDepth::Root,
        };

        // Test text output
        let mut element = classification.text(&Config::default()).unwrap();
        let canvas = element.render(None);
        let mut output = Vec::new();
        canvas.write(&mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        
        assert!(text.contains("classification:"));
        assert!(text.contains("is_ca: true"));
        assert!(text.contains("authenticates: Certificate Authority"));
        assert!(text.contains("depth: Root"));

        // Test JSON output
        let json = classification.json(&Config::default()).unwrap();
        let expected = json!({
            "is_ca": true,
            "authenticates": "ca",
            "depth": "root"
        });
        assert_eq!(json, expected);

        // Test leaf certificate
        let leaf_classification = CertClassification {
            is_ca: false,
            authenticates: CertUsage::Server,
            depth: CertDepth::Leaf,
        };

        let json = leaf_classification.json(&Config::default()).unwrap();
        let expected = json!({
            "is_ca": false,
            "authenticates": "server",
            "depth": "leaf"
        });
        assert_eq!(json, expected);
    }

    #[test]
    fn test_basic_constraints() {
        let constraints_ca = BasicConstraints {
            critical: true,
            is_ca: true,
            max_path_length: Some(5),
        };

        // Test text output
        let mut element = constraints_ca.text(&Config::default()).unwrap();
        let canvas = element.render(None);
        let mut output = Vec::new();
        canvas.write(&mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        
        assert!(text.contains("basic_constraints:"));
        assert!(text.contains("critical: true"));
        assert!(text.contains("is_ca: true"));
        assert!(text.contains("max_path_length: 5"));

        // Test JSON output
        let json = constraints_ca.json(&Config::default()).unwrap();
        let expected = json!({
            "critical": true,
            "is_ca": true,
            "max_path_length": 5
        });
        assert_eq!(json, expected);

        // Test leaf certificate constraints (no max_path_length)
        let constraints_leaf = BasicConstraints {
            critical: false,
            is_ca: false,
            max_path_length: None,
        };

        let json = constraints_leaf.json(&Config::default()).unwrap();
        let expected = json!({
            "critical": false,
            "is_ca": false
        });
        assert_eq!(json, expected);
    }
}