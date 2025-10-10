use certs_types::cert::Cert;
use iocraft::{
    AnyElement, Color, FlexDirection, Props, component, element,
    prelude::{Text, View},
};

use crate::impls::{expiry::ExpiryView, issuer::IssuerView, subject::SubjectView};

#[derive(Default, Props)]
pub(crate) struct CertViewProps {
    cert: Option<Cert>,
}

/// End goal is to look similar to:
/// ```no_test
///  subject: CN=cloudflare.com
///      dns: cloudflare.com *.amp.cloudflare.com *.cloudflare.com *.dns.cloudflare.com *.staging.cloudflare.com
///      ski: ba24f1a98a5769343f9ae873375e8973f06922ee
///      serial: 6da06fdfa90329010d3dd3414a3c2f28
///  not before: 2024-11-30T23:15:58Z (7mo 14d ago)
///  not after:  2025-03-01T00:15:55Z expired 4mo 14d ago
///  public key: id-ecPublicKey (256 bits)
///      group: prime256v1
///      key: 02fc29be7644b44d981051859e504de37fd7dc15cfc33e30f1a00c
///           5c456c641df5
///  usage: (critical) digital signature
///  issuer: C=US, O=Google Trust Services, CN=WE1
///      aki: 9077923567c4ffa8cca9e67bd980797bcc93f938
///      signature: ecdsa-with-SHA256
///          3046022100fe06845bc86825b16dcaf4fbafbd2be220f1be979333
///          c062c462cbccf12bc569022100c49de269efeeae0a9a29bbf6528f
///          080f585e3cf4053b8e4452b0746ebbbb645d
///  fingerprints:
///      sha256: c800f4e94178afe74079047e82445f10e25cb6f6c235ff2598838f87a985391e
///      sha1:   c9d6801195cdc64ad7763253fb379317fa9a2d34
///      md5:    b756f75c428239bd60990a4728eb3bfb
/// ```
#[component]
pub(crate) fn CertView(props: &CertViewProps) -> impl Into<AnyElement<'_>> {
    let Some(cert) = &props.cert else {
        return element! { View { Text(content: "no cert", color: Color::Red) } };
    };

    element! {
        View(flex_direction: FlexDirection::Column) {
            Text(content: "cert:", color: Color::Green)
            View(flex_direction: FlexDirection::Column, margin_left: 2) {
                SubjectView(subject: Some(&cert.subject), sans: Some(&cert.sans), ski: cert.ski.as_ref(), serial: Some(&cert.serial))
                ExpiryView(expiry: Some(&cert.expiry))
                // TODO: add PublicKeyView() with the public key
                // TODO: add UsageView() with the usage
                IssuerView(issuer: Some(&cert.issuer), aki: cert.aki.as_ref(), signature: Some(&cert.signature))
                // TODO: add FingerprintsView() with the fingerprints
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use certs_types::cert::Cert;
    use iocraft::element;

    use crate::impls::{cert::CertView, util::render_to_string};

    #[test]
    fn cert_view() {
        let cert = Cert::from_pem(include_bytes!(
            "../../../test-data/certs/cloudflare.com.pem"
        ))
        .unwrap();

        let output = render_to_string(element! { CertView(cert: Some(cert)) });
        println!("{}", output);
        // insta::assert_snapshot!(output);
    }
}
