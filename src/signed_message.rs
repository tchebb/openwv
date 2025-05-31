use cmac::{Mac, digest::KeyInit};
use prost::Message;
use thiserror::Error;

use crate::util::EnumPrinter;
use crate::video_widevine::SignedMessage;
use crate::video_widevine::signed_message::MessageType;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum SignedMessageError {
    #[error("bad protobuf serialization")]
    BadProto(#[from] prost::DecodeError),
    #[error("no message type in SignedMessage")]
    NoMessageType,
    #[error("wrong message type: expected {:?}, got {:?}", EnumPrinter::<MessageType>::from(*.expected), EnumPrinter::<MessageType>::from(*.actual))]
    WrongMessageType { actual: i32, expected: i32 },
    #[error("no signature in SignedMessage")]
    NoSignature,
    #[error("couldn't verify signature")]
    BadSignature,
    #[error("no inner message in SignedMessage")]
    NoMessage,
}

impl SignedMessage {
    pub fn decode_with_type(
        signed_message_bytes: &[u8],
        expected_type: MessageType,
    ) -> Result<Self, SignedMessageError> {
        let type_idx = expected_type as i32;

        let signed_message = SignedMessage::decode(signed_message_bytes)?;
        if signed_message.r#type != Some(type_idx) {
            return Err(signed_message.r#type.map_or(
                SignedMessageError::NoMessageType,
                |actual| SignedMessageError::WrongMessageType {
                    actual,
                    expected: type_idx,
                },
            ));
        }
        Ok(signed_message)
    }

    pub fn msg_checked(&self) -> Result<&[u8], SignedMessageError> {
        self.msg
            .as_ref()
            .ok_or(SignedMessageError::NoMessage)
            .map(Vec::as_slice)
    }

    pub fn verify_signature(&self, key: &[u8; 32]) -> Result<(), SignedMessageError> {
        let mut digester = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
        digester.update(self.msg_checked()?);
        let expected_sig = digester.finalize().into_bytes();

        let actual_sig = self
            .signature
            .as_ref()
            .ok_or(SignedMessageError::NoSignature)?;

        if actual_sig != expected_sig.as_slice() {
            Err(SignedMessageError::BadSignature)
        } else {
            Ok(())
        }
    }
}
