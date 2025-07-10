use certs_types::cert::{CertUsage, CertDepth};
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
}