use certs_types::cert::Cert;
use iocraft::{
    AnyElement, Color, element,
    prelude::{Text, View},
};

use crate::{Config, Repr};

impl Repr for Cert {
    fn text(&self, config: &Config) -> anyhow::Result<AnyElement<'static>> {
        let mut components = Vec::new();

        // Add all the major certificate components
        components.push(self.subject.text(config)?);
        components.push(self.issuer.text(config)?);
        components.push(self.expiry.text(config)?);
        components.push(self.classification.text(config)?);
        components.push(self.public_key.text(config)?);
        
        // Add signature information
        components.push(self.signature.text(config)?);
        
        // Add fingerprints
        components.push(self.fingerprints.text(config)?);
        
        // Add serial number
        components.push(self.serial.text(config)?);
        
        // Add basic constraints
        components.push(self.basic_constraints.text(config)?);
        
        // Add optional fields if they exist
        if let Some(ski) = &self.ski {
            components.push(ski.text(config)?);
        }
        
        if let Some(aki) = &self.aki {
            components.push(aki.text(config)?);
        }
        
        // Add SANs if they exist
        if !self.sans.dns.is_empty() || !self.sans.ip.is_empty() || 
           !self.sans.email.is_empty() || !self.sans.uri.is_empty() {
            components.push(self.sans.text(config)?);
        }

        Ok(element! { View {
            Text(content: "certificate:", color: Color::Green)
            View(gap: 1) {
                #(components)
            }
        }}.into_any())
    }

    fn json(&self, config: &Config) -> anyhow::Result<serde_json::Value> {
        let mut obj = serde_json::Map::new();
        
        // Add all the certificate components to the JSON object
        obj.insert("subject".to_string(), self.subject.json(config)?);
        obj.insert("issuer".to_string(), self.issuer.json(config)?);
        obj.insert("expiry".to_string(), self.expiry.json(config)?);
        obj.insert("classification".to_string(), self.classification.json(config)?);
        obj.insert("public_key".to_string(), self.public_key.json(config)?);
        obj.insert("signature".to_string(), self.signature.json(config)?);
        obj.insert("fingerprints".to_string(), self.fingerprints.json(config)?);
        obj.insert("serial".to_string(), self.serial.json(config)?);
        obj.insert("basic_constraints".to_string(), self.basic_constraints.json(config)?);
        
        // Add optional fields if they exist
        if let Some(ski) = &self.ski {
            obj.insert("ski".to_string(), ski.json(config)?);
        }
        
        if let Some(aki) = &self.aki {
            obj.insert("aki".to_string(), aki.json(config)?);
        }
        
        // Add SANs
        obj.insert("sans".to_string(), self.sans.json(config)?);
        
        // Add DER representation
        obj.insert("der".to_string(), serde_json::Value::String(format!("{:?}", self.der)));
        
        Ok(serde_json::Value::Object(obj))
    }
}

#[cfg(test)]
mod tests {
    use certs_types::{
        cert::{CertUsage, CertDepth, CertClassification, BasicConstraints},
        expiry::Expiry,
        id::{Serial, Ski, Aki, Digests},
        issuer::Issuer,
        key::{PublicKey, CertPublicKey, KeyUsage, ExtendedKeyUsage},
        sans::Sans,
        signature::Signature,
        subject::Subject,
        util::Hex,
        nid::Nid,
    };
    use iocraft::ElementExt;
    use jiff::Timestamp;
    use std::sync::Arc;
    use boring::nid::Nid as BoringNid;

    use super::*;

    #[test]
    fn test_cert_complete() {
        let cert = Cert {
            subject: Subject {
                common_name: Some(Arc::from("example.com")),
                organization: Some(Arc::from("Example Corp")),
                organization_unit: Some(Arc::from("IT Department")),
                country: Some(Arc::from("US")),
                state: Some(Arc::from("California")),
            },
            issuer: Issuer {
                subject: Subject {
                    common_name: Some(Arc::from("Example CA")),
                    organization: Some(Arc::from("Example Corp")),
                    organization_unit: Some(Arc::from("Certificate Authority")),
                    country: Some(Arc::from("US")),
                    state: Some(Arc::from("California")),
                },
            },
            expiry: Expiry {
                not_before: Timestamp::now(),
                not_after: Timestamp::now().checked_add(jiff::Span::new().seconds(365 * 24 * 60 * 60)).unwrap(),
            },
            classification: CertClassification {
                is_ca: false,
                authenticates: CertUsage::Server,
                depth: CertDepth::Leaf,
            },
            public_key: CertPublicKey {
                usage: KeyUsage {
                    critical: false,
                    digital_signature: true,
                    non_repudiation: false,
                    key_encipherment: false,
                    data_encipherment: false,
                    key_agreement: false,
                    key_cert_sign: false,
                    crl_sign: false,
                    encipher_only: false,
                    decipher_only: false,
                },
                extended_usage: ExtendedKeyUsage {
                    critical: false,
                    server_auth: true,
                    client_auth: false,
                    code_signing: false,
                    email_protection: false,
                    time_stamping: false,
                    ocsp_signing: false,
                },
                key: PublicKey::Ed25519 {
                    key: Hex::from_hex("abcd1234").unwrap(),
                },
                spki: Hex::from_hex("abcd5678").unwrap(),
            },
            signature: Signature {
                alg: Nid::from_boring(BoringNid::SHA256WITHRSAENCRYPTION),
                value: Hex::from_hex("deadbeef").unwrap(),
            },
            fingerprints: Digests {
                md5: Hex::from_hex("abcd1234").unwrap(),
                sha1: Hex::from_hex("def567890abcdef0").unwrap(),
                sha256: Hex::from_hex("1234567890abcdef1234567890abcdef12345678").unwrap(),
            },
            serial: Serial(Hex::from_hex("12345678").unwrap()),
            basic_constraints: BasicConstraints {
                critical: false,
                is_ca: false,
                max_path_length: None,
            },
            ski: Some(Ski(Hex::from_hex("abcdef12").unwrap())),
            aki: Some(Aki(Hex::from_hex("fedcba34").unwrap())),
            sans: Sans {
                dns: vec!["example.com".to_string(), "www.example.com".to_string()].into(),
                ip: vec![].into(),
                email: vec![].into(),
                uri: vec![].into(),
            },
            der: Hex::from_hex("abcdef56").unwrap(),
        };

        // Test text output
        let mut element = cert.text(&Config::default()).unwrap();
        let canvas = element.render(None);
        let mut output = Vec::new();
        canvas.write(&mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        
        assert!(text.contains("certificate:"));
        assert!(text.contains("subject:"));
        assert!(text.contains("issuer:"));
        assert!(text.contains("validity:"));
        assert!(text.contains("classification:"));

        // Test JSON output
        let json = cert.json(&Config::default()).unwrap();
        assert!(json.get("subject").is_some());
        assert!(json.get("issuer").is_some());
        assert!(json.get("expiry").is_some());
        assert!(json.get("classification").is_some());
        assert!(json.get("public_key").is_some());
        assert!(json.get("signature").is_some());
        assert!(json.get("fingerprints").is_some());
        assert!(json.get("serial").is_some());
        assert!(json.get("basic_constraints").is_some());
        assert!(json.get("ski").is_some());
        assert!(json.get("aki").is_some());
        assert!(json.get("sans").is_some());
        assert!(json.get("der").is_some());
    }
}