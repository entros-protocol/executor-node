use serde::{Deserialize, Serialize};
use solana_sdk::hash::hash;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;

use crate::error::AppError;
use crate::validation::handler::{
    ClientSignals, StudyCaptureClass, StudyRequestContext, ValidateFeaturesRequest,
};

const DIGEST_DOMAIN: &[u8] = b"entros-validate-request-digest-v1\0";
const MESSAGE_DOMAIN: &str = "Entros-Validate-v1";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalletAuthorization {
    pub nonce: Vec<u8>,
    pub signature_hex: String,
}

struct DigestEncoder {
    bytes: Vec<u8>,
}

impl DigestEncoder {
    fn new() -> Self {
        Self {
            bytes: DIGEST_DOMAIN.to_vec(),
        }
    }

    fn boolean(&mut self, value: bool) {
        self.bytes.push(u8::from(value));
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn length(&mut self, value: usize) -> Result<(), AppError> {
        let value = u32::try_from(value)
            .map_err(|_| AppError::InvalidRequest("Signed request field is too large".into()))?;
        self.u32(value);
        Ok(())
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), AppError> {
        self.length(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn string(&mut self, value: &str) -> Result<(), AppError> {
        self.bytes(value.as_bytes())
    }

    fn option_string(&mut self, value: Option<&str>) -> Result<(), AppError> {
        self.boolean(value.is_some());
        if let Some(value) = value {
            self.string(value)?;
        }
        Ok(())
    }

    fn finite_f64(&mut self, value: f64) -> Result<(), AppError> {
        if !value.is_finite() {
            return Err(AppError::InvalidRequest(
                "Signed request contains a non-finite number".into(),
            ));
        }
        let bits = if value == 0.0 { 0 } else { value.to_bits() };
        self.bytes.extend_from_slice(&bits.to_le_bytes());
        Ok(())
    }

    fn option_f64(&mut self, value: Option<f64>) -> Result<(), AppError> {
        self.boolean(value.is_some());
        if let Some(value) = value {
            self.finite_f64(value)?;
        }
        Ok(())
    }

    fn f64_vector(&mut self, values: &[f64]) -> Result<(), AppError> {
        self.length(values.len())?;
        for value in values {
            self.finite_f64(*value)?;
        }
        Ok(())
    }

    fn option_f64_vector(&mut self, values: Option<&[f64]>) -> Result<(), AppError> {
        self.boolean(values.is_some());
        if let Some(values) = values {
            self.f64_vector(values)?;
        }
        Ok(())
    }

    fn string_vector(&mut self, values: &[String]) -> Result<(), AppError> {
        self.length(values.len())?;
        for value in values {
            self.string(value)?;
        }
        Ok(())
    }

    fn client_signals(&mut self, signals: Option<&ClientSignals>) -> Result<(), AppError> {
        self.boolean(signals.is_some());
        let Some(signals) = signals else {
            return Ok(());
        };

        self.u32(signals.v);
        self.option_string(signals.env.as_deref())?;
        self.boolean(signals.automation.is_some());
        if let Some(automation) = signals.automation.as_ref() {
            self.boolean(automation.webdriver);
            self.string_vector(&automation.tells)?;
        }
        self.boolean(signals.capture.is_some());
        if let Some(capture) = signals.capture.as_ref() {
            self.boolean(capture.virtual_device);
            self.option_f64(capture.flatness)?;
            self.option_f64(capture.centroid)?;
        }
        Ok(())
    }

    fn study_context(&mut self, study: Option<&StudyRequestContext>) -> Result<(), AppError> {
        self.boolean(study.is_some());
        let Some(study) = study else {
            return Ok(());
        };

        self.string(&study.token)?;
        self.string(&study.record_id)?;
        self.u8(match study.capture_class {
            StudyCaptureClass::WebMobile => 0,
            StudyCaptureClass::WebDesktop => 1,
            StudyCaptureClass::NativeIos => 2,
            StudyCaptureClass::NativeAndroid => 3,
        });
        self.u16(study.feature_schema_version);
        self.u16(study.projection_version);
        Ok(())
    }

    fn finish(self) -> [u8; 32] {
        hash(&self.bytes).to_bytes()
    }
}

pub fn request_digest(request: &ValidateFeaturesRequest) -> Result<[u8; 32], AppError> {
    let mut encoder = DigestEncoder::new();
    encoder.boolean(request.baseline_reset);
    encoder.f64_vector(&request.features)?;

    encoder.boolean(request.compatibility_evidence.is_some());
    if let Some(evidence) = request.compatibility_evidence.as_ref() {
        encoder.u16(evidence.projection_version);
        encoder.u16(evidence.feature_schema_version);
        encoder.f64_vector(&evidence.features)?;
    }

    encoder.option_f64_vector(request.f0_contour.as_deref())?;
    encoder.option_f64_vector(request.accel_magnitude.as_deref())?;
    encoder.option_string(request.audio_samples_b64.as_deref())?;
    encoder.boolean(request.audio_sample_rate_hz.is_some());
    if let Some(sample_rate) = request.audio_sample_rate_hz {
        encoder.u32(sample_rate);
    }
    encoder.client_signals(request.client_signals.as_ref())?;
    encoder.study_context(request.study.as_ref())?;
    Ok(encoder.finish())
}

pub fn authorization_message(
    wallet: &Pubkey,
    nonce: &[u8; 32],
    projection_version: u16,
    digest: &[u8; 32],
) -> String {
    format!(
        "{MESSAGE_DOMAIN}\nwallet:{wallet}\nnonce:{}\nprojection:{projection_version}\nrequest_sha256:{}",
        lower_hex(nonce),
        lower_hex(digest),
    )
}

pub fn verify_wallet_authorization(
    request: &ValidateFeaturesRequest,
    wallet: &Pubkey,
    projection_version: u16,
) -> Result<Option<[u8; 32]>, AppError> {
    if projection_version != 2 {
        return if request.wallet_authorization.is_none() {
            Ok(None)
        } else {
            Err(AppError::InvalidRequest(
                "Wallet authorization is not allowed for this projection".into(),
            ))
        };
    }

    let authorization = request.wallet_authorization.as_ref().ok_or_else(|| {
        AppError::InvalidRequest("Projection 2 requires wallet authorization".into())
    })?;
    let nonce: [u8; 32] = authorization.nonce.as_slice().try_into().map_err(|_| {
        AppError::InvalidRequest("Wallet authorization nonce must be 32 bytes".into())
    })?;
    let signature_bytes = decode_lower_signature(&authorization.signature_hex)?;
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| AppError::Forbidden("Wallet authorization failed".into()))?;
    let digest = request_digest(request)?;
    let message = authorization_message(wallet, &nonce, projection_version, &digest);
    if request.wallet_id != wallet.to_string()
        || !signature.verify(wallet.as_ref(), message.as_bytes())
    {
        return Err(AppError::Forbidden("Wallet authorization failed".into()));
    }

    Ok(Some(nonce))
}

fn decode_lower_signature(value: &str) -> Result<[u8; 64], AppError> {
    if value.len() != 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(AppError::InvalidRequest(
            "Wallet authorization signature must be 128 lowercase hex characters".into(),
        ));
    }

    let mut output = [0_u8; 64];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => unreachable!("signature alphabet is checked before decoding"),
    }
}

fn lower_hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::handler::{
        AutomationSignals, CaptureSignals, ClientSignals, CurveTracePayload,
        ProjectionCompatibilityEvidence, StudyCaptureClass, StudyRequestContext,
        ValidateFeaturesRequest,
    };
    use solana_sdk::signature::{Keypair, Signer};

    fn request_fixture(wallet_id: String) -> ValidateFeaturesRequest {
        ValidateFeaturesRequest {
            features: vec![0.0, -0.0, 1.25],
            wallet_id,
            projection_version: Some(2),
            compatibility_evidence: Some(ProjectionCompatibilityEvidence {
                projection_version: 1,
                feature_schema_version: 4,
                features: vec![-0.0, 2.5],
            }),
            wallet_authorization: None,
            baseline_reset: true,
            f0_contour: Some(vec![-1.0, 0.5]),
            accel_magnitude: Some(vec![0.25]),
            audio_samples_b64: Some("AQID".into()),
            audio_sample_rate_hz: Some(16_000),
            _commitment_new_hex: None,
            _request_receipt: None,
            client_signals: Some(ClientSignals {
                v: 1,
                env: Some("browser".into()),
                automation: Some(AutomationSignals {
                    webdriver: true,
                    tells: vec!["selenium".into(), "playwright".into()],
                }),
                capture: Some(CaptureSignals {
                    virtual_device: false,
                    flatness: Some(0.125),
                    centroid: Some(2_400.0),
                }),
            }),
            curve_trace: None,
            capture_timing: None,
            study: Some(StudyRequestContext {
                token: "study-token".into(),
                record_id: "00112233445566778899aabbccddeeff".into(),
                capture_class: StudyCaptureClass::WebMobile,
                feature_schema_version: 5,
                projection_version: 2,
            }),
        }
    }

    fn signed_request(keypair: &Keypair, nonce: [u8; 32]) -> ValidateFeaturesRequest {
        let wallet = keypair.pubkey();
        let mut request = request_fixture(wallet.to_string());
        let digest = request_digest(&request).expect("fixture digest");
        let message = authorization_message(&wallet, &nonce, 2, &digest);
        request.wallet_authorization = Some(WalletAuthorization {
            nonce: nonce.to_vec(),
            signature_hex: lower_hex(keypair.sign_message(message.as_bytes()).as_ref()),
        });
        request
    }

    #[test]
    fn digest_and_message_match_the_golden_vector() {
        let wallet: solana_sdk::pubkey::Pubkey = "11111111111111111111111111111111"
            .parse()
            .expect("valid wallet");
        let request = request_fixture(wallet.to_string());
        let nonce = [0x5a; 32];
        let digest = request_digest(&request).expect("fixture digest");

        assert_eq!(
            lower_hex(&digest),
            "a629314bf11f266689983f629f55c299789c9fca387e34593a8d323661d5f21a"
        );
        assert_eq!(
            authorization_message(&wallet, &nonce, 2, &digest),
            concat!(
                "Entros-Validate-v1\n",
                "wallet:11111111111111111111111111111111\n",
                "nonce:5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a\n",
                "projection:2\n",
                "request_sha256:a629314bf11f266689983f629f55c299789c9fca387e34593a8d323661d5f21a",
            )
        );
    }

    #[test]
    fn digest_normalizes_negative_zero() {
        let mut negative = request_fixture("11111111111111111111111111111111".into());
        let mut positive = request_fixture("11111111111111111111111111111111".into());
        negative.features[0] = -0.0;
        positive.features[0] = 0.0;
        negative.compatibility_evidence.as_mut().unwrap().features[0] = -0.0;
        positive.compatibility_evidence.as_mut().unwrap().features[0] = 0.0;

        assert_eq!(
            request_digest(&negative).unwrap(),
            request_digest(&positive).unwrap()
        );
    }

    #[test]
    fn every_verdict_affecting_field_changes_the_digest() {
        let baseline =
            request_digest(&request_fixture("11111111111111111111111111111111".into())).unwrap();
        let mutations: &[fn(&mut ValidateFeaturesRequest)] = &[
            |request| request.baseline_reset = false,
            |request| request.features[0] = 9.0,
            |request| {
                request
                    .compatibility_evidence
                    .as_mut()
                    .unwrap()
                    .projection_version = 0
            },
            |request| {
                request
                    .compatibility_evidence
                    .as_mut()
                    .unwrap()
                    .feature_schema_version = 3
            },
            |request| request.compatibility_evidence.as_mut().unwrap().features[0] = 9.0,
            |request| request.f0_contour.as_mut().unwrap()[0] = 9.0,
            |request| request.accel_magnitude.as_mut().unwrap()[0] = 9.0,
            |request| request.audio_samples_b64 = Some("BAUG".into()),
            |request| request.audio_sample_rate_hz = Some(48_000),
            |request| request.client_signals.as_mut().unwrap().v = 2,
            |request| request.client_signals.as_mut().unwrap().env = Some("native".into()),
            |request| {
                request
                    .client_signals
                    .as_mut()
                    .unwrap()
                    .automation
                    .as_mut()
                    .unwrap()
                    .webdriver = false
            },
            |request| {
                request
                    .client_signals
                    .as_mut()
                    .unwrap()
                    .automation
                    .as_mut()
                    .unwrap()
                    .tells
                    .push("extra".into())
            },
            |request| {
                request
                    .client_signals
                    .as_mut()
                    .unwrap()
                    .capture
                    .as_mut()
                    .unwrap()
                    .virtual_device = true
            },
            |request| {
                request
                    .client_signals
                    .as_mut()
                    .unwrap()
                    .capture
                    .as_mut()
                    .unwrap()
                    .flatness = Some(0.5)
            },
            |request| {
                request
                    .client_signals
                    .as_mut()
                    .unwrap()
                    .capture
                    .as_mut()
                    .unwrap()
                    .centroid = Some(4_800.0)
            },
        ];

        for mutation in mutations {
            let mut request = request_fixture("11111111111111111111111111111111".into());
            mutation(&mut request);
            assert_ne!(request_digest(&request).unwrap(), baseline);
        }
    }

    #[test]
    fn observe_only_fields_do_not_change_the_digest() {
        let mut request = request_fixture("11111111111111111111111111111111".into());
        let baseline = request_digest(&request).unwrap();
        request.curve_trace = Some(CurveTracePayload {
            points: vec![[1.0, 2.0]],
            duration_ms: 500.0,
        });
        request.capture_timing = Some(serde_json::json!({ "v": 1, "coverage": 0.9 }));

        assert_eq!(request_digest(&request).unwrap(), baseline);
    }

    #[test]
    fn study_context_is_digest_bound_field_by_field() {
        let baseline =
            request_digest(&request_fixture("11111111111111111111111111111111".into())).unwrap();
        let mutations: &[fn(&mut ValidateFeaturesRequest)] = &[
            |request| request.study = None,
            |request| request.study.as_mut().unwrap().token.push('x'),
            |request| request.study.as_mut().unwrap().record_id.push('0'),
            |request| request.study.as_mut().unwrap().capture_class = StudyCaptureClass::WebDesktop,
            |request| request.study.as_mut().unwrap().feature_schema_version = 4,
            |request| request.study.as_mut().unwrap().projection_version = 1,
        ];

        for mutation in mutations {
            let mut request = request_fixture("11111111111111111111111111111111".into());
            mutation(&mut request);
            assert_ne!(request_digest(&request).unwrap(), baseline);
        }
    }

    #[test]
    fn projection_two_requires_a_valid_wallet_signature() {
        let keypair = Keypair::new();
        let nonce = [0x33; 32];
        let request = signed_request(&keypair, nonce);

        assert_eq!(
            verify_wallet_authorization(&request, &keypair.pubkey(), 2).unwrap(),
            Some(nonce)
        );
    }

    #[test]
    fn signed_request_rejects_tampering() {
        let keypair = Keypair::new();
        let mut request = signed_request(&keypair, [0x44; 32]);
        request.features[0] = 7.0;

        assert!(verify_wallet_authorization(&request, &keypair.pubkey(), 2).is_err());
    }

    #[test]
    fn authorization_policy_and_fixed_widths_fail_closed() {
        let keypair = Keypair::new();
        let mut request = signed_request(&keypair, [0x55; 32]);
        assert!(verify_wallet_authorization(&request, &keypair.pubkey(), 1).is_err());

        request.wallet_authorization = None;
        assert!(verify_wallet_authorization(&request, &keypair.pubkey(), 2).is_err());
        assert_eq!(
            verify_wallet_authorization(&request, &keypair.pubkey(), 1).unwrap(),
            None
        );

        request = signed_request(&keypair, [0x55; 32]);
        request.wallet_authorization.as_mut().unwrap().nonce.pop();
        assert!(verify_wallet_authorization(&request, &keypair.pubkey(), 2).is_err());

        request = signed_request(&keypair, [0x55; 32]);
        request
            .wallet_authorization
            .as_mut()
            .unwrap()
            .signature_hex
            .pop();
        assert!(verify_wallet_authorization(&request, &keypair.pubkey(), 2).is_err());

        request = signed_request(&keypair, [0x55; 32]);
        request
            .wallet_authorization
            .as_mut()
            .unwrap()
            .signature_hex
            .replace_range(0..1, "A");
        assert!(verify_wallet_authorization(&request, &keypair.pubkey(), 2).is_err());
    }
}
