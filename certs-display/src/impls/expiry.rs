use certs_types::expiry::Expiry;
use iocraft::{
    AnyElement, Color, element,
    prelude::{Text, View},
};
use jiff::Timestamp;

use crate::{Config, Repr};

impl Repr for Expiry {
    fn text(&self, _config: &Config) -> anyhow::Result<AnyElement<'static>> {
        // Check if the certificate is expired or expires soon
        let now = Timestamp::now();
        let status = if now > self.not_after {
            ("EXPIRED", Color::Red)
        } else if now < self.not_before {
            ("NOT YET VALID", Color::Yellow)
        } else {
            // Check if expires within 30 days (30 * 24 * 60 * 60 seconds)
            let thirty_days = jiff::Span::new().seconds(30 * 24 * 60 * 60);
            if let Ok(warning_time) = now.checked_add(thirty_days) {
                if warning_time > self.not_after {
                    ("EXPIRES SOON", Color::Yellow)
                } else {
                    ("VALID", Color::Green)
                }
            } else {
                ("VALID", Color::Green)
            }
        };

        Ok(element! { View {
            Text(content: "validity:", color: Color::Green)
            View(gap: 1) {
                View {
                    Text(content: "  not_before: ", color: Color::Green)
                    Text(content: self.not_before.strftime("%Y-%m-%d %H:%M:%S UTC").to_string())
                }
                View {
                    Text(content: "  not_after: ", color: Color::Green)
                    Text(content: self.not_after.strftime("%Y-%m-%d %H:%M:%S UTC").to_string())
                }
                View {
                    Text(content: "  status: ", color: Color::Green)
                    Text(content: status.0, color: status.1)
                }
            }
        }}.into_any())
    }

    fn json(&self, _config: &Config) -> anyhow::Result<serde_json::Value> {
        let mut obj = serde_json::Map::new();
        
        obj.insert("not_before".to_string(), 
                   serde_json::Value::String(self.not_before.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()));
        obj.insert("not_after".to_string(), 
                   serde_json::Value::String(self.not_after.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()));
        
        // Add status information
        let now = Timestamp::now();
        let status = if now > self.not_after {
            "expired"
        } else if now < self.not_before {
            "not_yet_valid"
        } else {
            "valid"
        };
        obj.insert("status".to_string(), serde_json::Value::String(status.to_string()));
        
        Ok(serde_json::Value::Object(obj))
    }
}

#[cfg(test)]
mod tests {
    use iocraft::ElementExt;
    use jiff::Timestamp;
    use serde_json::json;

    use super::*;

    #[test]
    fn test_valid_expiry() {
        let now = Timestamp::now();
        let one_year = jiff::Span::new().seconds(365 * 24 * 60 * 60);
        
        let expiry = Expiry {
            not_before: now.checked_sub(jiff::Span::new().seconds(24 * 60 * 60)).unwrap(),
            not_after: now.checked_add(one_year).unwrap(),
        };

        // Test text output
        let mut element = expiry.text(&Config::default()).unwrap();
        let canvas = element.render(None);
        let mut output = Vec::new();
        canvas.write(&mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        
        assert!(text.contains("validity:"));
        assert!(text.contains("not_before:"));
        assert!(text.contains("not_after:"));
        assert!(text.contains("status:"));

        // Test JSON output
        let json = expiry.json(&Config::default()).unwrap();
        assert!(json.get("not_before").is_some());
        assert!(json.get("not_after").is_some());
        assert!(json.get("status").is_some());
        assert_eq!(json.get("status").unwrap(), &json!("valid"));
    }

    #[test]
    fn test_expired_expiry() {
        let now = Timestamp::now();
        let one_day = jiff::Span::new().seconds(24 * 60 * 60);
        
        let expiry = Expiry {
            not_before: now.checked_sub(jiff::Span::new().seconds(365 * 24 * 60 * 60)).unwrap(),
            not_after: now.checked_sub(one_day).unwrap(),
        };

        // Test JSON output for expired certificate
        let json = expiry.json(&Config::default()).unwrap();
        assert_eq!(json.get("status").unwrap(), &json!("expired"));
    }

    #[test]
    fn test_future_expiry() {
        let now = Timestamp::now();
        let one_day = jiff::Span::new().seconds(24 * 60 * 60);
        
        let expiry = Expiry {
            not_before: now.checked_add(one_day).unwrap(),
            not_after: now.checked_add(jiff::Span::new().seconds(365 * 24 * 60 * 60)).unwrap(),
        };

        // Test JSON output for not yet valid certificate
        let json = expiry.json(&Config::default()).unwrap();
        assert_eq!(json.get("status").unwrap(), &json!("not_yet_valid"));
    }
}