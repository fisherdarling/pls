use certs_types::subject::Subject;
use iocraft::{
    AnyElement, Color, element,
    prelude::{Text, View},
};

use crate::{Config, Repr};

impl Repr for Subject {
    fn text(&self, _config: &Config) -> anyhow::Result<AnyElement<'static>> {
        let mut components = Vec::new();

        if let Some(common_name) = &self.common_name {
            components.push(element! { View {
                Text(content: "cn: ", color: Color::Green)
                Text(content: common_name.as_ref())
            }});
        }

        if let Some(organization) = &self.organization {
            components.push(element! { View {
                Text(content: "o: ", color: Color::Green)
                Text(content: organization.as_ref())
            }});
        }

        if let Some(organization_unit) = &self.organization_unit {
            components.push(element! { View {
                Text(content: "ou: ", color: Color::Green)
                Text(content: organization_unit.as_ref())
            }});
        }

        if let Some(country) = &self.country {
            components.push(element! { View {
                Text(content: "c: ", color: Color::Green)
                Text(content: country.as_ref())
            }});
        }

        if let Some(state) = &self.state {
            components.push(element! { View {
                Text(content: "st: ", color: Color::Green)
                Text(content: state.as_ref())
            }});
        }

        Ok(element! { View {
            Text(content: "subject: ", color: Color::Green)
            View(gap: 1) {
                #(components)
            }
        }}
        .into_any())
    }

    fn json(&self, _config: &Config) -> anyhow::Result<serde_json::Value> {
        let mut obj = serde_json::Map::new();

        if let Some(common_name) = &self.common_name {
            obj.insert(
                "cn".to_string(),
                serde_json::Value::String(common_name.as_ref().to_string()),
            );
        }

        if let Some(organization) = &self.organization {
            obj.insert(
                "o".to_string(),
                serde_json::Value::String(organization.as_ref().to_string()),
            );
        }

        if let Some(organization_unit) = &self.organization_unit {
            obj.insert(
                "ou".to_string(),
                serde_json::Value::String(organization_unit.as_ref().to_string()),
            );
        }

        if let Some(country) = &self.country {
            obj.insert(
                "c".to_string(),
                serde_json::Value::String(country.as_ref().to_string()),
            );
        }

        if let Some(state) = &self.state {
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

    use super::*;

    #[test]
    fn test_full_subject() {
        let subject = Subject {
            common_name: Some(Arc::from("example.com")),
            organization: Some(Arc::from("Example Corp")),
            organization_unit: Some(Arc::from("IT Department")),
            country: Some(Arc::from("US")),
            state: Some(Arc::from("California")),
        };

        let mut element = subject.text(&Config::default()).unwrap();

        element.print();

        let canvas = element.render(None);

        let mut output = Vec::new();
        canvas.write(&mut output).unwrap();

        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("subject:"));
        assert!(text.contains("cn: example.com"));
        assert!(text.contains("o: Example Corp"));
        assert!(text.contains("ou: IT Department"));
        assert!(text.contains("c: US"));
        assert!(text.contains("st: California"));

        let json = subject.json(&Config::default()).unwrap();
        let expected = json!({
            "cn": "example.com",
            "o": "Example Corp",
            "ou": "IT Department",
            "c": "US",
            "st": "California"
        });
        assert_eq!(json, expected);
    }

    #[test]
    fn test_empty_subject() {
        let subject = Subject {
            common_name: None,
            organization: None,
            organization_unit: None,
            country: None,
            state: None,
        };

        let mut element = subject.text(&Config::default()).unwrap();
        let canvas = element.render(None);

        let mut output = Vec::new();
        canvas.write(&mut output).unwrap();

        let text = String::from_utf8(output).unwrap();
        assert_eq!(text, "subject:\n");

        let json = subject.json(&Config::default()).unwrap();
        assert_eq!(json, json!({}));
    }

    #[test]
    fn test_partial_subject() {
        let subject = Subject {
            common_name: Some(Arc::from("test.example.com")),
            organization: None,
            organization_unit: None,
            country: Some(Arc::from("CA")),
            state: None,
        };

        let json = subject.json(&Config::default()).unwrap();
        let expected = json!({
            "cn": "test.example.com",
            "c": "CA"
        });
        assert_eq!(json, expected);
    }
}
