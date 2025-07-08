use certs_types::sans::Sans;
use iocraft::{
    AnyElement, Color, element,
    prelude::{Text, View},
};

use crate::{Config, Repr};

impl Repr for Sans {
    fn text(&self, _config: &Config) -> anyhow::Result<AnyElement<'static>> {
        let dns = (!self.dns.is_empty()).then(|| {
            element! { View {
                Text(content: format!("dns: "), color: Color::Green)
                Text(content: format!("{:?}", self.dns))
            }}
        });

        let ip = (!self.ip.is_empty()).then(|| {
            element! { View {
                Text(content: format!("ip: "), color: Color::Green)
                Text(content: format!("{:?}", self.ip))
            }}
        });

        let uri = (!self.uri.is_empty()).then(|| {
            element! { View {
                Text(content: format!("uri: "), color: Color::Green)
                Text(content: format!("{:?}", self.uri))
            }}
        });

        let email = (!self.email.is_empty()).then(|| {
            element! { View {
                Text(content: format!("email: "), color: Color::Green)
                Text(content: format!("{:?}", self.email))
            }}
        });

        Ok(element! { View {
          Text(content: format!("sans: "), color: Color::Green)
          #(dns)
          #(ip)
          #(email)
          #(uri)
        }}
        .into_any())
    }
    fn json(&self, _config: &Config) -> anyhow::Result<serde_json::Value> {
        let mut obj = serde_json::Map::new();
        if !self.dns.is_empty() {
            obj.insert(
                "dns".to_string(),
                serde_json::Value::Array(
                    self.dns
                        .iter()
                        .map(|s| serde_json::Value::String(s.clone()))
                        .collect(),
                ),
            );
        }
        if !self.ip.is_empty() {
            obj.insert(
                "ip".to_string(),
                serde_json::Value::Array(
                    self.ip
                        .iter()
                        .map(|s| serde_json::Value::String(s.to_string()))
                        .collect(),
                ),
            );
        }
        if !self.email.is_empty() {
            obj.insert(
                "email".to_string(),
                serde_json::Value::Array(
                    self.email
                        .iter()
                        .map(|s| serde_json::Value::String(s.clone()))
                        .collect(),
                ),
            );
        }
        if !self.uri.is_empty() {
            obj.insert(
                "uri".to_string(),
                serde_json::Value::Array(
                    self.uri
                        .iter()
                        .map(|s| serde_json::Value::String(s.clone()))
                        .collect(),
                ),
            );
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
    fn test_empty_sans() {
        let sans = Sans::default();
        let mut element = sans.text(&Config::default()).unwrap();
        let canvas = element.render(None);

        let mut output = Vec::new();
        canvas.write(&mut output).unwrap();

        let text = String::from_utf8(output).unwrap();
        assert_eq!(text, "sans:\n");

        let json = sans.json(&Config::default()).unwrap();
        assert_eq!(json, json!({}));
    }
}
