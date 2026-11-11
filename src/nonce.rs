use ring::{aead::{NONCE_LEN, Nonce, NonceSequence}, error::Unspecified};

pub struct OneTimeNonce {
    nonce: Option<Nonce>,
}

impl OneTimeNonce {
    pub fn new(nonce_bytes: [u8; NONCE_LEN]) -> Self {
        Self {
            nonce: Some(Nonce::assume_unique_for_key(nonce_bytes)),
        }
    }
}

impl NonceSequence for OneTimeNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.nonce.take().ok_or(Unspecified)
    }
}