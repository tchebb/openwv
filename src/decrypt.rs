use aes::cipher::{BlockModeDecrypt, KeyIvInit, StreamCipher};
use thiserror::Error;

use crate::content_key::ContentKey;
use crate::ffi::cdm;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum DecryptError {
    #[error("key needed but not present")]
    NoKey,
    #[error("no iv provided for ciphered scheme")]
    NoIv,
    #[error("incorrect key or iv length")]
    BadKeyIvLength(#[from] aes::cipher::InvalidLength),
    #[error("integer overflow")]
    Overflow(#[from] std::num::TryFromIntError),
    #[error("subsamples exceed data length")]
    ShortData,
}

pub fn decrypt_buf(
    key: Option<&ContentKey>,
    iv: Option<&[u8]>,
    data: &mut [u8],
    mode: cdm::EncryptionScheme,
    subsamples: Option<&[cdm::SubsampleEntry]>,
    pattern: &cdm::Pattern,
) -> Result<(), DecryptError> {
    use cdm::EncryptionScheme::*;

    match (mode, key, iv) {
        (kUnencrypted, _, _) => Ok(()),
        (kCenc, Some(key), Some(iv)) => {
            let mut decryptor = match iv.len() {
                len if len < 16 => {
                    // IV is only 8 bytes for CTR mode. Chromium zero-pads it
                    // to 16 bytes, but Firefox doesn't. Pad if needed.
                    let mut padded_iv = [0u8; 16];
                    padded_iv[..len].copy_from_slice(iv);
                    ctr::Ctr64BE::<aes::Aes128>::new_from_slices(key.data.as_slice(), &padded_iv)?
                }
                16 => ctr::Ctr64BE::<aes::Aes128>::new_from_slices(key.data.as_slice(), iv)?,
                _ => return Err(aes::cipher::InvalidLength.into()),
            };

            decrypt_possible_subsamples(data, subsamples, |ciphered| {
                decryptor.apply_keystream(ciphered);
            })
        }
        (kCbcs, Some(key), Some(iv)) => {
            let pattern_skip = usize::try_from(pattern.skip_byte_block)?;
            let mut pattern_crypt = usize::try_from(pattern.crypt_byte_block)?;

            // https://source.chromium.org/chromium/chromium/src/+/main:media/cdm/cbcs_decryptor.cc;l=65-69;drc=2fdecb20631b358fed488a177af773d92f85d35c
            if pattern_skip == 0 && pattern_crypt == 0 {
                pattern_crypt = 1;
            }

            let mut decryptor =
                cbc::Decryptor::<aes::Aes128>::new_from_slices(key.data.as_slice(), iv)?;

            decrypt_possible_subsamples(data, subsamples, |ciphered| {
                decrypt_pattern(ciphered, &mut decryptor, pattern_skip, pattern_crypt);
            })
        }
        (_, None, _) => Err(DecryptError::NoKey),
        (_, _, None) => Err(DecryptError::NoIv),
    }
}

fn decrypt_possible_subsamples(
    data: &mut [u8],
    subsamples_opt: Option<&[cdm::SubsampleEntry]>,
    mut decrypt: impl FnMut(&mut [u8]),
) -> Result<(), DecryptError> {
    // If there aren't any subsamples, our job is really easy.
    let Some(subsamples) = subsamples_opt else {
        decrypt(data);
        return Ok(());
    };

    let mut remaining = data;
    for subsample in subsamples {
        let ciphered_start = usize::try_from(subsample.clear_bytes)?;
        let ciphered_end = ciphered_start + usize::try_from(subsample.cipher_bytes)?;
        let ciphered = remaining
            .get_mut(ciphered_start..ciphered_end)
            .ok_or(DecryptError::ShortData)?;

        decrypt(ciphered);

        remaining = &mut remaining[ciphered_end..];
    }
    Ok(())
}

fn decrypt_pattern(
    data: &mut [u8],
    decryptor: &mut cbc::Decryptor<aes::Aes128>,
    pattern_skip: usize,
    pattern_crypt: usize,
) {
    let mut blocks = data.chunks_exact_mut(16);
    while blocks.len() > 0 {
        for block in blocks.by_ref().take(pattern_crypt) {
            decryptor.decrypt_block(block.try_into().unwrap());
        }

        blocks.by_ref().take(pattern_skip).for_each(drop);
    }
}
