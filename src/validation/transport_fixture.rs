use base64::{engine::general_purpose, Engine as _};
use serde_json::{json, Value};

use crate::server::MAX_REQUEST_BODY_BYTES;
use crate::validation::handler::ValidateFeaturesRequest;

pub(crate) const REPRESENTATIVE_DURATION_MS: usize = 12_000;
pub(crate) const MAXIMUM_DURATION_MS: usize = 20_000;
pub(crate) const SAMPLE_RATE_HZ: usize = 16_000;

const BINARY_MAGIC: &[u8; 4] = b"ENTV";
const BINARY_VERSION: u16 = 1;
const BINARY_FLAGS_PCM16_LE: u16 = 1;
const BINARY_HEADER_LEN: usize = 16;

#[derive(Debug, PartialEq, Eq)]
enum BinaryEnvelopeError {
    Oversized,
    TruncatedHeader,
    BadMagic,
    UnsupportedVersion,
    UnsupportedFlags,
    TruncatedBody,
    TrailingBytes,
    InvalidPcmLength,
    MalformedMetadata,
    DuplicateAudio,
}

struct DecodedBinaryTransport {
    request: ValidateFeaturesRequest,
    pcm_bytes: Vec<u8>,
}

pub(crate) struct SyntheticTransportFixture {
    pub(crate) request: Value,
    pub(crate) pcm_bytes: Vec<u8>,
}

pub(crate) fn synthetic_transport_fixture(duration_ms: usize) -> SyntheticTransportFixture {
    let sample_count = SAMPLE_RATE_HZ * duration_ms / 1_000;
    let mut pcm_bytes = Vec::with_capacity(sample_count * 2);
    for index in 0..sample_count {
        let sample = (((index * 1_103 + 7_919) & 0xffff) as i32 - 32_768) as i16;
        pcm_bytes.extend_from_slice(&sample.to_le_bytes());
    }

    let features = feature_vector(16.0);
    let compatibility_features = feature_vector(32.0);
    let contour_len = duration_ms / 10;
    let f0_contour: Vec<f64> = (0..contour_len)
        .map(|index| 80.0 + (index % 37) as f64 / 2.0)
        .collect();
    let accel_magnitude: Vec<f64> = (0..contour_len)
        .map(|index| ((index % 29) as f64 - 14.0) / 64.0)
        .collect();
    let outline: Vec<[f64; 2]> = (0..64)
        .map(|index| {
            [
                index as f64 * 100.0 / 63.0,
                ((index * 17) % 64) as f64 * 100.0 / 63.0,
            ]
        })
        .collect();

    let request = json!({
        "features": features,
        "wallet_id": "11111111111111111111111111111111",
        "projection_version": 2,
        "compatibility_evidence": {
            "projection_version": 1,
            "feature_schema_version": 4,
            "features": compatibility_features,
        },
        "wallet_authorization": {
            "nonce": vec![0x5a_u8; 32],
            "signature_hex": "ab".repeat(64),
        },
        "baseline_reset": false,
        "f0_contour": f0_contour,
        "accel_magnitude": accel_magnitude,
        "audio_samples_b64": general_purpose::STANDARD.encode(&pcm_bytes),
        "audio_sample_rate_hz": SAMPLE_RATE_HZ,
        "commitment_new_hex": "11".repeat(32),
        "request_receipt": true,
        "client_signals": {
            "v": 1,
            "env": "non-browser",
            "automation": { "webdriver": false, "tells": [] },
            "capture": {
                "virtual_device": false,
                "voice_isolation_applied": null,
                "flatness": 0.125,
                "centroid": 2_400.0,
            },
        },
        "curve_trace": {
            "points": outline,
            "duration_ms": duration_ms,
        },
    });

    SyntheticTransportFixture { request, pcm_bytes }
}

pub(crate) fn padded_request_body(duration_ms: usize, target_len: usize) -> Vec<u8> {
    let mut request = synthetic_transport_fixture(duration_ms).request;
    request["padding"] = Value::String(String::new());
    let empty = serde_json::to_vec(&request).expect("synthetic request serializes");
    assert!(empty.len() <= target_len, "target must fit the fixture");
    request["padding"] = Value::String("x".repeat(target_len - empty.len()));
    let body = serde_json::to_vec(&request).expect("padded request serializes");
    assert_eq!(body.len(), target_len);
    body
}

fn binary_transport_envelope(request: &Value, pcm_bytes: &[u8]) -> Vec<u8> {
    let mut metadata = request.clone();
    let object = metadata
        .as_object_mut()
        .expect("synthetic request metadata is an object");
    let encoded_audio = object
        .remove("audio_samples_b64")
        .and_then(|value| value.as_str().map(str::to_owned))
        .expect("synthetic request has encoded audio");
    assert_eq!(
        general_purpose::STANDARD
            .decode(encoded_audio)
            .expect("synthetic audio is base64"),
        pcm_bytes
    );
    let metadata = serde_json::to_vec(&metadata).expect("synthetic metadata serializes");
    binary_envelope_from_parts(&metadata, pcm_bytes)
}

fn binary_envelope_from_parts(metadata: &[u8], pcm_bytes: &[u8]) -> Vec<u8> {
    let metadata_len = u32::try_from(metadata.len()).expect("test metadata length fits u32");
    let pcm_len = u32::try_from(pcm_bytes.len()).expect("test PCM length fits u32");
    let mut envelope = Vec::with_capacity(BINARY_HEADER_LEN + metadata.len() + pcm_bytes.len());
    envelope.extend_from_slice(BINARY_MAGIC);
    envelope.extend_from_slice(&BINARY_VERSION.to_le_bytes());
    envelope.extend_from_slice(&BINARY_FLAGS_PCM16_LE.to_le_bytes());
    envelope.extend_from_slice(&metadata_len.to_le_bytes());
    envelope.extend_from_slice(&pcm_len.to_le_bytes());
    envelope.extend_from_slice(metadata);
    envelope.extend_from_slice(pcm_bytes);
    envelope
}

fn decode_binary_transport(body: &[u8]) -> Result<DecodedBinaryTransport, BinaryEnvelopeError> {
    if body.len() > MAX_REQUEST_BODY_BYTES {
        return Err(BinaryEnvelopeError::Oversized);
    }
    if body.len() < BINARY_HEADER_LEN {
        return Err(BinaryEnvelopeError::TruncatedHeader);
    }
    if &body[..4] != BINARY_MAGIC {
        return Err(BinaryEnvelopeError::BadMagic);
    }
    let version = u16::from_le_bytes([body[4], body[5]]);
    if version != BINARY_VERSION {
        return Err(BinaryEnvelopeError::UnsupportedVersion);
    }
    let flags = u16::from_le_bytes([body[6], body[7]]);
    if flags != BINARY_FLAGS_PCM16_LE {
        return Err(BinaryEnvelopeError::UnsupportedFlags);
    }
    let metadata_len = u32::from_le_bytes([body[8], body[9], body[10], body[11]]) as usize;
    let pcm_len = u32::from_le_bytes([body[12], body[13], body[14], body[15]]) as usize;
    if pcm_len == 0 || pcm_len % 2 != 0 {
        return Err(BinaryEnvelopeError::InvalidPcmLength);
    }
    let metadata_end = BINARY_HEADER_LEN
        .checked_add(metadata_len)
        .ok_or(BinaryEnvelopeError::TruncatedBody)?;
    let envelope_end = metadata_end
        .checked_add(pcm_len)
        .ok_or(BinaryEnvelopeError::TruncatedBody)?;
    if body.len() < envelope_end {
        return Err(BinaryEnvelopeError::TruncatedBody);
    }
    if body.len() > envelope_end {
        return Err(BinaryEnvelopeError::TrailingBytes);
    }

    let mut metadata: Value = serde_json::from_slice(&body[BINARY_HEADER_LEN..metadata_end])
        .map_err(|_| BinaryEnvelopeError::MalformedMetadata)?;
    let object = metadata
        .as_object_mut()
        .ok_or(BinaryEnvelopeError::MalformedMetadata)?;
    if object.contains_key("audio_samples_b64") {
        return Err(BinaryEnvelopeError::DuplicateAudio);
    }
    let pcm_bytes = body[metadata_end..envelope_end].to_vec();
    object.insert(
        "audio_samples_b64".into(),
        Value::String(general_purpose::STANDARD.encode(&pcm_bytes)),
    );
    let request =
        serde_json::from_value(metadata).map_err(|_| BinaryEnvelopeError::MalformedMetadata)?;
    Ok(DecodedBinaryTransport { request, pcm_bytes })
}

fn feature_vector(divisor: f64) -> Vec<f64> {
    (0..308)
        .map(|index| (index as f64 - 154.0) / divisor)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::authorization::request_digest;

    fn assert_decode_error(body: &[u8], expected: BinaryEnvelopeError) {
        match decode_binary_transport(body) {
            Err(actual) => assert_eq!(actual, expected),
            Ok(_) => panic!("invalid binary envelope decoded"),
        }
    }

    #[test]
    fn synthetic_transport_binary_round_trips_match_json_semantics() {
        for duration_ms in [REPRESENTATIVE_DURATION_MS, MAXIMUM_DURATION_MS] {
            let fixture = synthetic_transport_fixture(duration_ms);
            let json_request: ValidateFeaturesRequest =
                serde_json::from_value(fixture.request.clone()).expect("JSON fixture deserializes");
            let envelope = binary_transport_envelope(&fixture.request, &fixture.pcm_bytes);
            assert_eq!(&envelope[..4], BINARY_MAGIC);
            assert_eq!(
                u16::from_le_bytes([envelope[4], envelope[5]]),
                BINARY_VERSION
            );
            assert_eq!(
                u16::from_le_bytes([envelope[6], envelope[7]]),
                BINARY_FLAGS_PCM16_LE
            );
            let metadata_len =
                u32::from_le_bytes([envelope[8], envelope[9], envelope[10], envelope[11]]) as usize;
            let pcm_len =
                u32::from_le_bytes([envelope[12], envelope[13], envelope[14], envelope[15]])
                    as usize;
            assert_eq!(pcm_len, fixture.pcm_bytes.len());
            let metadata_end = BINARY_HEADER_LEN + metadata_len;
            let metadata: Value =
                serde_json::from_slice(&envelope[BINARY_HEADER_LEN..metadata_end])
                    .expect("binary metadata is JSON");
            assert!(metadata.get("audio_samples_b64").is_none());
            assert_eq!(&envelope[metadata_end..], fixture.pcm_bytes);
            let decoded = decode_binary_transport(&envelope).expect("binary fixture decodes");

            assert_eq!(decoded.pcm_bytes, fixture.pcm_bytes);
            assert_eq!(&decoded.request.wallet_id, &json_request.wallet_id);
            assert_eq!(decoded.request.projection_version, Some(2));
            assert_eq!(
                decoded.request.audio_sample_rate_hz,
                json_request.audio_sample_rate_hz
            );
            assert_eq!(
                decoded.request.audio_samples_b64.as_deref(),
                json_request.audio_samples_b64.as_deref()
            );
            assert_eq!(
                request_digest(&decoded.request).expect("binary request digest"),
                request_digest(&json_request).expect("JSON request digest")
            );
            assert_eq!(decoded.request.features, json_request.features);
            assert_eq!(decoded.request.f0_contour, json_request.f0_contour);
            assert_eq!(
                decoded.request.accel_magnitude,
                json_request.accel_magnitude
            );
            let decoded_compatibility = decoded
                .request
                .compatibility_evidence
                .as_ref()
                .expect("binary compatibility exists");
            let json_compatibility = json_request
                .compatibility_evidence
                .as_ref()
                .expect("JSON compatibility exists");
            assert_eq!(
                decoded_compatibility.projection_version,
                json_compatibility.projection_version
            );
            assert_eq!(
                decoded_compatibility.feature_schema_version,
                json_compatibility.feature_schema_version
            );
            assert_eq!(decoded_compatibility.features, json_compatibility.features);
            let decoded_authorization = decoded
                .request
                .wallet_authorization
                .as_ref()
                .expect("binary authorization exists");
            let json_authorization = json_request
                .wallet_authorization
                .as_ref()
                .expect("JSON authorization exists");
            assert_eq!(decoded_authorization.nonce, json_authorization.nonce);
            assert_eq!(
                decoded_authorization.signature_hex,
                json_authorization.signature_hex
            );
        }
    }

    #[test]
    fn synthetic_transport_binary_round_trips_projection_one() {
        let fixture = synthetic_transport_fixture(REPRESENTATIVE_DURATION_MS);
        let mut request = fixture.request;
        request["projection_version"] = json!(1);
        let object = request
            .as_object_mut()
            .expect("synthetic request is an object");
        object.remove("compatibility_evidence");
        object.remove("wallet_authorization");

        let json_request: ValidateFeaturesRequest =
            serde_json::from_value(request.clone()).expect("JSON fixture deserializes");
        let envelope = binary_transport_envelope(&request, &fixture.pcm_bytes);
        let decoded = decode_binary_transport(&envelope).expect("binary fixture decodes");

        assert_eq!(decoded.request.projection_version, Some(1));
        assert!(decoded.request.compatibility_evidence.is_none());
        assert!(decoded.request.wallet_authorization.is_none());
        assert_eq!(
            request_digest(&decoded.request).expect("binary request digest"),
            request_digest(&json_request).expect("JSON request digest")
        );
    }

    #[test]
    fn synthetic_transport_binary_rejects_invalid_framing() {
        let fixture = synthetic_transport_fixture(REPRESENTATIVE_DURATION_MS);
        let envelope = binary_transport_envelope(&fixture.request, &fixture.pcm_bytes);

        assert_decode_error(
            &envelope[..BINARY_HEADER_LEN - 1],
            BinaryEnvelopeError::TruncatedHeader,
        );

        let mut truncated_body = envelope.clone();
        truncated_body.pop();
        assert_decode_error(&truncated_body, BinaryEnvelopeError::TruncatedBody);

        let truncated_metadata = &envelope[..BINARY_HEADER_LEN + 1];
        assert_decode_error(truncated_metadata, BinaryEnvelopeError::TruncatedBody);

        let mut bad_magic = envelope.clone();
        bad_magic[0] ^= 0xff;
        assert_decode_error(&bad_magic, BinaryEnvelopeError::BadMagic);

        let mut unknown_version = envelope.clone();
        unknown_version[4..6].copy_from_slice(&2_u16.to_le_bytes());
        assert_decode_error(&unknown_version, BinaryEnvelopeError::UnsupportedVersion);

        for flags in [0_u16, 2_u16] {
            let mut unsupported_flags = envelope.clone();
            unsupported_flags[6..8].copy_from_slice(&flags.to_le_bytes());
            assert_decode_error(&unsupported_flags, BinaryEnvelopeError::UnsupportedFlags);
        }

        let mut trailing_bytes = envelope.clone();
        trailing_bytes.push(0);
        assert_decode_error(&trailing_bytes, BinaryEnvelopeError::TrailingBytes);

        assert_decode_error(
            &vec![0_u8; MAX_REQUEST_BODY_BYTES + 1],
            BinaryEnvelopeError::Oversized,
        );
    }

    #[test]
    fn synthetic_transport_binary_rejects_invalid_pcm_lengths() {
        let metadata = br#"{"features":[],"wallet_id":"11111111111111111111111111111111"}"#;
        for pcm_bytes in [&[][..], &[0_u8][..]] {
            let envelope = binary_envelope_from_parts(metadata, pcm_bytes);
            assert_decode_error(&envelope, BinaryEnvelopeError::InvalidPcmLength);
        }
    }

    #[test]
    fn synthetic_transport_binary_rejects_invalid_metadata() {
        let fixture = synthetic_transport_fixture(REPRESENTATIVE_DURATION_MS);

        let malformed = binary_envelope_from_parts(b"not-json", &fixture.pcm_bytes);
        assert_decode_error(&malformed, BinaryEnvelopeError::MalformedMetadata);

        let non_object = binary_envelope_from_parts(b"[]", &fixture.pcm_bytes);
        assert_decode_error(&non_object, BinaryEnvelopeError::MalformedMetadata);

        let missing_fields = binary_envelope_from_parts(b"{}", &fixture.pcm_bytes);
        assert_decode_error(&missing_fields, BinaryEnvelopeError::MalformedMetadata);

        let duplicate_audio = binary_envelope_from_parts(
            &serde_json::to_vec(&fixture.request).expect("fixture serializes"),
            &fixture.pcm_bytes,
        );
        assert_decode_error(&duplicate_audio, BinaryEnvelopeError::DuplicateAudio);
    }
}
