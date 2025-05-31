use aes::cipher::{BlockModeDecrypt, KeyIvInit};
use byteorder::{BE, ByteOrder};
use cmac::{Mac, digest::KeyInit};
use log::info;
use prost::Message;
use rand::{Rng, TryRngCore};
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use thiserror::Error;

use crate::content_key::ContentKey;
use crate::service_certificate::{ServerCertificate, encrypt_client_id};
use crate::util::now;
use crate::video_widevine;
use crate::wvd_file::WidevineDevice;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum LicenseError {
    #[error("bad license encapsulation: {0}")]
    BadSignedMessage(#[from] crate::signed_message::SignedMessageError),
    #[error("bad protobuf serialization")]
    BadProto(#[from] prost::DecodeError),
    #[error("no key in SignedMessage")]
    NoSessionKey,
    #[error("couldn't decrypt key: {0}")]
    BadSessionKeyCrypto(#[from] rsa::Error),
    #[error("incorrect key or iv length")]
    BadKeyIvLength(#[from] aes::cipher::InvalidLength),
    #[error("bad padding in content key")]
    BadContentKey(#[from] aes::cipher::block_padding::UnpadError),
}

pub fn request_license(
    content_id: video_widevine::license_request::ContentIdentification,
    server_certificate: Option<&ServerCertificate>,
    device: &WidevineDevice,
) -> (video_widevine::SignedMessage, Vec<u8>) {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let key_control_nonce: u32 = rng.random();

    let mut req = video_widevine::LicenseRequest {
        content_id: Some(content_id),
        r#type: Some(video_widevine::license_request::RequestType::New as i32),
        request_time: Some(now()),
        protocol_version: Some(video_widevine::ProtocolVersion::Version21 as i32),
        key_control_nonce: Some(key_control_nonce),
        ..Default::default()
    };

    match server_certificate {
        None => req.client_id = Some(device.client_id.clone()),
        Some(cert) => req.encrypted_client_id = Some(encrypt_client_id(cert, &device.client_id)),
    }

    let req_bytes = req.encode_to_vec();

    let signing_key = rsa::pss::SigningKey::<sha1::Sha1>::new(device.private_key.clone());
    let signature = signing_key.sign_with_rng(&mut rng, &req_bytes).to_vec();

    let req_bytes_for_sig = req_bytes.clone();
    (
        video_widevine::SignedMessage {
            r#type: Some(video_widevine::signed_message::MessageType::LicenseRequest as i32),
            msg: Some(req_bytes),
            signature: Some(signature),
            ..Default::default()
        },
        req_bytes_for_sig,
    )
}

pub fn load_license_keys(
    response_bytes: &[u8],
    request_bytes: &[u8],
    device: &WidevineDevice,
    keys: &mut Vec<ContentKey>,
) -> Result<bool, LicenseError> {
    let response = video_widevine::SignedMessage::decode_with_type(
        response_bytes,
        video_widevine::signed_message::MessageType::License,
    )?;

    let wrapped_key = response
        .session_key
        .as_ref()
        .ok_or(LicenseError::NoSessionKey)?;

    let padding = rsa::Oaep::new::<sha1::Sha1>();
    let session_key = device.private_key.decrypt(padding, wrapped_key)?;
    let session_keys = derive_session_keys(request_bytes, &session_key)?;

    response.verify_signature(&session_keys.mac_server)?;

    let license = video_widevine::License::decode(response.msg_checked()?)?;

    let mut added_keys = false;
    for key in license.key {
        let (Some(iv), Some(mut data)) = (key.iv, key.key) else {
            continue;
        };

        let decryptor =
            cbc::Decryptor::<aes::Aes128>::new_from_slices(&session_keys.encryption, &iv)?;
        let new_size = decryptor
            .decrypt_padded::<aes::cipher::block_padding::Pkcs7>(&mut data)?
            .len();
        data.truncate(new_size);

        let track_label = match key.track_label {
            Some(l) if l.is_empty() => None,
            x => x,
        };

        let new_key = ContentKey {
            id: key.id,
            data,
            key_type: key.r#type,
            track_label,
        };

        info!("Loaded key: {}", &new_key);
        keys.push(new_key);
        added_keys = true;
    }

    Ok(added_keys)
}

#[derive(Debug)]
struct SessionKeys {
    encryption: [u8; 16],
    mac_server: [u8; 32],
    #[allow(dead_code)]
    mac_client: [u8; 32],
}

fn derive_session_keys(
    request_msg: &[u8],
    session_key: &[u8],
) -> Result<SessionKeys, cmac::digest::InvalidLength> {
    let mut cmac = cmac::Cmac::<aes::Aes128>::new_from_slice(session_key)?;

    let mut derive_key = |counter, label, key_size| {
        cmac.update(&[counter]);
        cmac.update(label);
        cmac.update(&[0]);
        cmac.update(request_msg);

        let mut buf = [0u8; 4];
        BE::write_u32(&mut buf, key_size);
        cmac.update(&buf);

        cmac.finalize_reset().into_bytes()
    };

    let encryption = derive_key(1, b"ENCRYPTION", 128).into();

    const AUTH_LABEL: &[u8] = b"AUTHENTICATION";

    let mut mac_server = [0u8; 32];
    mac_server[..16].copy_from_slice(derive_key(1, AUTH_LABEL, 512).as_slice());
    mac_server[16..].copy_from_slice(derive_key(2, AUTH_LABEL, 512).as_slice());

    let mut mac_client = [0u8; 32];
    mac_client[..16].copy_from_slice(derive_key(3, AUTH_LABEL, 512).as_slice());
    mac_client[16..].copy_from_slice(derive_key(4, AUTH_LABEL, 512).as_slice());

    Ok(SessionKeys {
        encryption,
        mac_server,
        mac_client,
    })
}
