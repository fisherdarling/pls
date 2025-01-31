use iocraft::prelude::*;
use jiff::Zoned;

use crate::{
    commands::Format,
    components::round_relative_human,
    theme::{HIGHLIGHT_COLOR, KEY_WIDTH, TOP_LEVEL_COLOR},
    x509::{
        BasicConstraints, Fingerprints, Issuer, Signature, SimpleCert, SimpleCsr, SimpleKeyUsage,
        SimplePublicKey, SimplePublicKeyKind, Subject, Validity,
    },
};

#[derive(Default, Props)]
pub struct Props {
    pub cert: SimpleCert,
}

#[component]
pub fn X509View(props: &Props) -> impl Into<AnyElement<'static>> {
    element! {
        View(flex_direction: FlexDirection::Column) {
            SubjectView(subject: props.cert.subject.clone(), serial: props.cert.serial.clone())
            ValidityView(validity: props.cert.validity.clone())
            PublicKeyView(public_key: props.cert.public_key.clone())
            UsageView(key_usage: props.cert.key_usage.clone(), basic_constraints: props.cert.extensions.basic_constraints.clone())
            IssuerView(issuer: props.cert.issuer.clone(), id: props.cert.aki.clone(), signature: props.cert.signature.clone())
            FingerprintsView(fingerprints: props.cert.fingerprints.clone())
        }
    }
}

#[derive(Default, Props)]
pub struct SubjectProps {
    pub subject: Subject,
    pub serial: Option<String>,
}

#[component]
pub fn SubjectView(props: &SubjectProps) -> impl Into<AnyElement<'static>> {
    let dns = (!props.subject.sans.dns.is_empty()).then(|| {
        element! {
            View(gap: 1) {
                Text(content: "dns:") {}
                #(props.subject.sans.dns.iter().map(|dns| {
                    element! { Text(content: dns, color: HIGHLIGHT_COLOR, decoration: TextDecoration::Underline) }
                }))
            }
        }
    });

    let ip = (!props.subject.sans.ip.is_empty()).then(|| {
        element! {
            View(gap: 1) {
                Text(content: "ip:") {}
                #(props.subject.sans.ip.iter().map(|ip| {
                    element! { Text(content: ip.to_string(), decoration: TextDecoration::Underline, color: Color::Cyan) }
                }))
            }
        }
    });

    let email = (!props.subject.sans.email.is_empty()).then(|| {
        element! {
            View(gap: 1) {
                Text(content: "email:", color: Color::Yellow) {}
                #(props.subject.sans.email.iter().map(|email| {
                    element! { Text(content: email, decoration: TextDecoration::Underline) }
                }))
            }
        }
    });

    element! {
        View(flex_direction: FlexDirection::Column) {
            View(gap: 1) {
                Text(content: "subject:", color: TOP_LEVEL_COLOR) {}
                Text(content: &props.subject.name)
            }
            View(margin_left: 4, flex_direction: FlexDirection::Column) {
                #(dns)
                #(ip)
                #(email)
            }
            #(props.subject.ski.clone().map(|ski| {
                element! {
                    View(margin_left: 4) {
                        Text(content: "ski: ") {}
                        Text(content: ski)
                    }
                }
            }))
            #(props.serial.clone().map(|serial| {
                element! {
                    View(margin_left: 4) {
                        Text(content: "serial: ") {}
                        Text(content: serial)
                    }
                }
            }))
        }
    }
}

#[derive(Default, Props)]
pub struct ValidityProps {
    pub validity: Validity,
}

#[component]
fn ValidityView(props: &ValidityProps) -> impl Into<AnyElement<'static>> {
    let zoned_now = Zoned::now();
    let now = zoned_now.timestamp();
    let expires_in = now.until(props.validity.not_after).unwrap();
    let valid_in = now.until(props.validity.not_before).unwrap();

    let rounded_valid_in = round_relative_human(valid_in, zoned_now.clone());
    let not_before_text = if valid_in.signum() < 0 {
        // it's became valid in the past
        element! {
            SurroundText(
                left: "(",
                text: format!("{:#}", rounded_valid_in),
                right: ")"
            )
        }
    } else {
        // it's not valid yet
        element! {
            SurroundText(
                left: "(in ",
                text: format!("{:#}", rounded_valid_in),
                right: ")  "
            )
        }
    };

    let rounded_expires_in = round_relative_human(expires_in, zoned_now);
    let expires_in_text = if expires_in.signum() < 0 {
        // it expired in the future, so it's still valid
        element! {
            Text(content: format!("expired {:#}", rounded_expires_in), color: Color::Red, decoration: TextDecoration::Underline, weight: Weight::Bold)
        }
        .into_any()
    } else {
        // it expired in the future, so it's still valid
        element! {
            SurroundText(
                left: "(in ",
                text: format!("{:#}", rounded_expires_in),
                right: ")    "
            )
        }
        .into_any()
    };

    let expired = now >= props.validity.not_after;

    // todo: add time validity:
    let _is_valid_text = props
        .validity
        .valid
        .unwrap_or(!expired)
        .then(|| {
            element! {
                Text(content: "✅")
            }
        })
        .unwrap_or_else(|| {
            element! {
                Text(content: format!("🚨 {}", props.validity.verify_result.clone().unwrap_or_default()), color: Color::Red, decoration: TextDecoration::Underline)
            }
        });

    let verify_result_text = props.validity.verify_result.clone().map(|result| {
        element! {
            Text(content: format!("🚨 {result}"), color: Color::Red, decoration: TextDecoration::Underline)
        }
    });

    element! {
        View(flex_direction: FlexDirection::Column) {
            #(verify_result_text)
            View(gap: 1, flex_direction: FlexDirection::Row) {
                Text(content: "not before:", color: TOP_LEVEL_COLOR)
                Text(content: props.validity.not_before.to_string())
                #(not_before_text)
            }
            View(gap: 1, flex_direction: FlexDirection::Row) {
                Text(content: "not after: ", color: TOP_LEVEL_COLOR)
                Text(content: props.validity.not_after.to_string())
                #(expires_in_text)
            }
        }
    }
}

#[derive(Default, Props)]
pub struct SurroundTextProps {
    pub left: &'static str,
    pub text: String,
    pub right: &'static str,
    pub color: Option<Color>,
}

#[component]
pub fn SurroundText(props: &SurroundTextProps) -> impl Into<AnyElement<'static>> {
    element! {
        View() {
            Text(content: props.left)
            #(props.color.map(|color| element! {
                Text(content: props.text.clone(), color: color)
            }).unwrap_or_else(|| element! {
                Text(content: props.text.clone())
            }))
            Text(content: props.right)
        }
    }
}

#[derive(Default, Props)]
pub struct PublicKeyProps {
    public_key: SimplePublicKey,
}

#[component]
pub fn PublicKeyView(props: &PublicKeyProps) -> impl Into<AnyElement<'static>> {
    let public_key_element = match &props.public_key.kind {
        SimplePublicKeyKind::EC { group, key } => {
            element! {
                View(flex_direction: FlexDirection::Column) {
                    #(group.map(|nid| {
                        element! {
                            View() {
                                Text(content: "group: ") {}
                                Text(content: nid.short_name().unwrap(), color: HIGHLIGHT_COLOR)
                            }
                        }
                    }))
                    View(gap: 1) {
                        Text(content: "key:") {}
                        View(width: KEY_WIDTH) {
                            Text(content: key.clone()) {}
                        }
                    }
                }
            }
        }
        SimplePublicKeyKind::RSA {
            modulus, exponent, ..
        } => {
            element! {
                View(flex_direction: FlexDirection::Column) {
                    View(gap: 1) {
                        Text(content: "exponent:") {}
                        Text(content: exponent.to_string())
                    }
                    View(gap: 1) {
                        Text(content: "modulus:") {}
                        View(width: KEY_WIDTH) {
                            Text(content: modulus.clone())
                        }
                    }
                }
            }
        }
        // todo: the rest of the key types
        key => todo!("{:?} not implemented", key),
    };

    element! {
        View(flex_direction: FlexDirection::Column) {
            View(gap: 1) {
                Text(content: "public key:", color: TOP_LEVEL_COLOR) {}
                Text(content: format!("{} ({} bits)", props.public_key.curve.nid().short_name().unwrap(), props.public_key.bits))
            }
            View(margin_left: 4) {
                #(public_key_element)
            }
        }
    }
}

#[derive(Default, Props)]
pub struct SignatureProps {
    pub signature: Signature,
    pub top_level: bool,
}

#[component]
pub fn SignatureView(props: &SignatureProps) -> impl Into<AnyElement<'static>> {
    element! {
        View(flex_direction: FlexDirection::Column) {
            View(gap: 1) {
                #(props.top_level.then(|| element! {
                    Text(content: "signature:", color: TOP_LEVEL_COLOR)
                }).unwrap_or_else(|| element! {
                    Text(content: "signature:")
                }))
                Text(content: props.signature.algorithm.clone())
            }
            View(margin_left: 4, width: KEY_WIDTH) {
                Text(content: props.signature.value.clone(), wrap: TextWrap::Wrap)
            }
        }
    }
}

#[derive(Default, Props)]
pub struct IssuerProps {
    pub issuer: Issuer,
    pub id: Option<String>,
    pub signature: Signature,
}

#[component]
pub fn IssuerView(props: &IssuerProps) -> impl Into<AnyElement<'static>> {
    element! {
        View(flex_direction: FlexDirection::Column) {
            View() {
                Text(content: "issuer: ", color: TOP_LEVEL_COLOR) {}
                Text(content: format!("{}", props.issuer.name))
            }
            #(props.id.clone().map(|id| {
                element! {
                    View(margin_left: 4) {
                        Text(content: "aki: ") {}
                        Text(content: id)
                    }
                }
            }))
            View(margin_left: 4) {
                SignatureView(signature: props.signature.clone())
            }
        }
    }
}

#[derive(Default, Props)]
pub struct UsageProps {
    pub key_usage: SimpleKeyUsage,
    pub basic_constraints: Option<BasicConstraints>,
}

#[component]
pub fn UsageView(props: &UsageProps) -> impl Into<AnyElement<'static>> {
    let mut key_usage_text = String::new();
    if props.key_usage.digital_signature {
        key_usage_text.push_str("digital signature");
    }
    if props.key_usage.content_commitment {
        if !key_usage_text.is_empty() {
            key_usage_text.push_str(", ");
        }
        key_usage_text.push_str("content commitment");
    }
    if props.key_usage.key_encipherment {
        if !key_usage_text.is_empty() {
            key_usage_text.push_str(", ");
        }
        key_usage_text.push_str("key encipherment");
    }
    if props.key_usage.data_encipherment {
        if !key_usage_text.is_empty() {
            key_usage_text.push_str(", ");
        }
        key_usage_text.push_str("data encipherment");
    }
    if props.key_usage.key_agreement {
        if !key_usage_text.is_empty() {
            key_usage_text.push_str(", ");
        }
        key_usage_text.push_str("key agreement");
    }
    if props.key_usage.key_cert_sign {
        if !key_usage_text.is_empty() {
            key_usage_text.push_str(", ");
        }
        key_usage_text.push_str("key cert sign");
    }
    if props.key_usage.crl_sign {
        if !key_usage_text.is_empty() {
            key_usage_text.push_str(", ");
        }
        key_usage_text.push_str("crl sign");
    }
    if props.key_usage.encipher_only {
        if !key_usage_text.is_empty() {
            key_usage_text.push_str(", ");
        }
        key_usage_text.push_str("encipher only");
    }
    if props.key_usage.decipher_only {
        if !key_usage_text.is_empty() {
            key_usage_text.push_str(", ");
        }
        key_usage_text.push_str("decipher only");
    }

    let key_usage = element! {
        View(gap: 1) {
            #(props.key_usage.critical.then(|| element! {
                View(gap: 1) {
                    Text(content: "usage:", color: TOP_LEVEL_COLOR)
                    Text(content: "(critical)")
                }
            }.into_any()).unwrap_or_else(|| element! {
                Text(content: "usage: ", color: TOP_LEVEL_COLOR)
            }.into_any()))
            Text(content: key_usage_text, color: HIGHLIGHT_COLOR)
        }
    };

    // todo: implement basic constraints
    element! {
        View(flex_direction: FlexDirection::Column) {
            #(key_usage)
            // #(basic_constraints)
        }
    }
}

#[derive(Default, Props)]
pub struct FingerprintsProps {
    pub fingerprints: Fingerprints,
}

#[component]
pub fn FingerprintsView(props: &FingerprintsProps) -> impl Into<AnyElement<'static>> {
    element! {
        View(flex_direction: FlexDirection::Column) {
            Text(content: "fingerprints:", color: TOP_LEVEL_COLOR)
            View(flex_direction: FlexDirection::Column, margin_left: 4) {
                Text(content: format!("sha256: {}", props.fingerprints.sha256))
                Text(content: format!("sha1:   {}", props.fingerprints.sha1))
                Text(content: format!("md5:    {}", props.fingerprints.md5))
            }
        }
    }
}

#[derive(Default, Props)]
pub struct MultipleCertViewProps {
    pub certs: Vec<SimpleCert>,
}

#[component]
pub fn MultipleCertView(props: &MultipleCertViewProps) -> impl Into<AnyElement<'static>> {
    element! {
        View(flex_direction: FlexDirection::Column, gap: 1) {
            #(props.certs.iter().cloned().enumerate().map(|(i, cert)| element!(
                View(flex_direction: FlexDirection::Column) {
                    #((props.certs.len() > 1).then(|| element! {
                        Text(content: format!("cert #{}:", i + 1), color: Color::Magenta)
                    }))
                    X509View(cert)
                }
            )))
        }
    }
}
#[derive(Default, Props)]
pub struct CsrProps {
    csr: SimpleCsr,
}

#[component]
pub fn CsrView(props: &CsrProps) -> impl Into<AnyElement<'static>> {
    element! {
        View(flex_direction: FlexDirection::Column) {
            SubjectView(subject: props.csr.subject.clone(), serial: None)
            PublicKeyView(public_key: props.csr.public_key.clone())
            SignatureView(signature: props.csr.signature.clone(), top_level: true)
        }
    }
}

#[derive(Default, Props)]
pub struct MultipleCsrViewProps {
    pub csrs: Vec<SimpleCsr>,
}

#[component]
pub fn MultipleCsrView(props: &MultipleCsrViewProps) -> impl Into<AnyElement<'static>> {
    element! {
        View(flex_direction: FlexDirection::Column, gap: 1) {
            #(props.csrs.iter().cloned().enumerate().map(|(i, csr)| element!(
                View(flex_direction: FlexDirection::Column) {
                    #((props.csrs.len() > 1).then(|| element! {
                        Text(content: format!("csr #{}:", i + 1), color: Color::Magenta)
                    }))
                    CsrView(csr)
                }
            )))
        }
    }
}

pub fn print_csrs(csrs: Vec<SimpleCsr>, format: Format) -> color_eyre::Result<()> {
    tracing::info!("printing {} csrs in {format:?} format", csrs.len());
    match format {
        Format::Text => {
            element! {
                View(margin: 1) {
                    MultipleCsrView(csrs)
                }
            }
            .print();
        }
        Format::Json => {
            println!("{}", serde_json::to_string_pretty(&csrs)?);
        }
        Format::Pem => {
            for csr in csrs {
                print!("{}", csr.pem);
            }
        }
    }

    Ok(())
}

pub fn print_certs(certs: Vec<SimpleCert>, format: Format) -> color_eyre::Result<()> {
    tracing::info!("printing {} certs in {format:?} format", certs.len());
    match format {
        Format::Text => {
            element! {
                View(margin: 1) {
                    MultipleCertView(certs)
                }
            }
            .print();
        }
        Format::Json => {
            println!("{}", serde_json::to_string_pretty(&certs)?);
        }
        Format::Pem => {
            for cert in certs {
                print!("{}", cert.pem);
            }
        }
    }

    Ok(())
}
