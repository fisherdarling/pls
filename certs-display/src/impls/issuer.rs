use certs_types::issuer::Issuer;
use iocraft::{
    AnyElement, Color, element,
    prelude::{Text, View},
};

use crate::{Config, Repr};

impl Repr for Issuer {
    fn text(&self, _config: &Config) -> anyhow::Result<AnyElement<'static>> {
        let mut components = Vec::new();

        if let Some(common_name) = &self.subject.common_name {
            components.push(element! { View {
                Text(content: "cn: ", color: Color::Green)
                Text(content: common_name.as_ref())
            }});
        }

        if let Some(organization) = &self.subject.organization {
            components.push(element! { View {
                Text(content: "o: ", color: Color::Green)
                Text(content: organization.as_ref())
            }});
        }

        if let Some(organization_unit) = &self.subject.organization_unit {
            components.push(element! { View {
                Text(content: "ou: ", color: Color::Green)
                Text(content: organization_unit.as_ref())
            }});
        }

        if let Some(country) = &self.subject.country {
            components.push(element! { View {
                Text(content: "c: ", color: Color::Green)
                Text(content: country.as_ref())
            }});
        }

        if let Some(state) = &self.subject.state {
            components.push(element! { View {
                Text(content: "st: ", color: Color::Green)
                Text(content: state.as_ref())
            }});
        }

        Ok(element! { View {
            Text(content: "issuer: ", color: Color::Green)
            View(gap: 1) {
                #(components)
            }
        }}
        .into_any())
    }

    fn json(&self, _config: &Config) -> anyhow::Result<serde_json::Value> {
        let mut obj = serde_json::Map::new();

        if let Some(common_name) = &self.subject.common_name {
            obj.insert(
                "cn".to_string(),
                serde_json::Value::String(common_name.as_ref().to_string()),
            );
        }

        if let Some(organization) = &self.subject.organization {
            obj.insert(
                "o".to_string(),
                serde_json::Value::String(organization.as_ref().to_string()),
            );
        }

        if let Some(organization_unit) = &self.subject.organization_unit {
            obj.insert(
                "ou".to_string(),
                serde_json::Value::String(organization_unit.as_ref().to_string()),
            );
        }

        if let Some(country) = &self.subject.country {
            obj.insert(
                "c".to_string(),
                serde_json::Value::String(country.as_ref().to_string()),
            );
        }

        if let Some(state) = &self.subject.state {
            obj.insert(
                "st".to_string(),
                serde_json::Value::String(state.as_ref().to_string()),
            );
        }

        Ok(serde_json::Value::Object(obj))
    }
}

#[cfg(test)]
mod tests {
    use iocraft::ElementExt;
    use serde_json::json;
    use std::sync::Arc;
    use certs_types::subject::Subject;

    use super::*;

    #[test]
    fn test_full_issuer() {
        let issuer = Issuer {
            subject: Subject {
                common_name: Some(Arc::from("Example CA")),
                organization: Some(Arc::from("Example Corp")),
                organization_unit: Some(Arc::from("Certificate Authority")),
                country: Some(Arc::from("US")),
                state: Some(Arc::from("California")),
            },
        };

        let mut element = issuer.text(&Config::default()).unwrap();

        element.print();

        let canvas = element.render(None);

        let mut output = Vec::new();
        canvas.write(&mut output).unwrap();

        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("issuer:"));
        assert!(text.contains("cn: Example CA"));
        assert!(text.contains("o: Example Corp"));
        assert!(text.contains("ou: Certificate Authority"));
        assert!(text.contains("c: US"));
        assert!(text.contains("st: California"));

        let json = issuer.json(&Config::default()).unwrap();
        let expected = json!({
            "cn": "Example CA",
            "o": "Example Corp",
            "ou": "Certificate Authority",
            "c": "US",
            "st": "California"
        });
        assert_eq!(json, expected);
    }

    #[test]
    fn test_empty_issuer() {
        let issuer = Issuer {
            subject: Subject {
                common_name: None,
                organization: None,
                organization_unit: None,
                country: None,
                state: None,
            },
        };

        let mut element = issuer.text(&Config::default()).unwrap();
        let canvas = element.render(None);

        let mut output = Vec::new();
        canvas.write(&mut output).unwrap();

        let text = String::from_utf8(output).unwrap();
        assert_eq!(text, "issuer:\n");

        let json = issuer.json(&Config::default()).unwrap();
        assert_eq!(json, json!({}));
    }

    #[test]
    fn test_partial_issuer() {
        let issuer = Issuer {
            subject: Subject {
                common_name: Some(Arc::from("Root CA")),
                organization: None,
                organization_unit: None,
                country: Some(Arc::from("CA")),
                state: None,
            },
        };

        let json = issuer.json(&Config::default()).unwrap();
        let expected = json!({
            "cn": "Root CA",
            "c": "CA"
        });
        assert_eq!(json, expected);
    }
}