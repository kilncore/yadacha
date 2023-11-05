#![no_std]

pub trait Yadacha {
    // Encoding
    fn init_encode(&mut self, associated_data: &[u8]);
    fn encode(&mut self, data: &mut [u8]);
    fn finalize(&mut self) -> &[u8]; // returns tag.
    // Decoding
    fn init_decode(&mut self, associated_data: &[u8]);
    fn decode(&mut self, data: &mut [u8]);
    fn validate(&mut self, tag: &[u8]) -> bool;
    // Random position decoding, no validation.
    fn seek_and_decode(&mut self, byte_index: u64, data: &mut [u8]);
}

pub mod yadacha16k; // Yadacha16k reuses parts of the original ChaCha20 cipher.
pub type Key16k = [[u8; 1 << 8]; 64];   // 64 x 8 bits s-boxes, 16 KB.
pub type Nonce16k = [u32; 8];           // 256 bits nonce.
pub type MsgNonce16k = [u32; 2];        // 64 bits msg-nonce.

pub mod yadacha8m; // Yadacha8m extends the cipher from u32 to u64.
pub type Key8m = [[u16; 1 << 16]; 64];  // 64 x 16 bits s-boxes, 8 MB.
pub type Nonce8m = [u64; 8];            // 512 bits nonce.
pub type MsgNonce8m = [u64; 2];         // 128 bits msg-nonce.

#[cfg(target_pointer_width = "64")]
pub mod yadacha1t; // Yadacha1t extends the cipher from u64 to u128.
pub type Key1t = [[u32; 1 << 32]; 64];  // 64 x 32 bits s-boxes, 1 TB.
pub type Nonce1t = [u128; 8];           // 1024 bits nonce.
pub type MsgNonce1t = [u128; 2];        // 256 bits msg-nonce.

#[cfg(target_pointer_width = "64")]
pub mod yadacha10t; // Yadacha10t uses a different tables at each dual-round.
pub type Key10t = [Key1t; 10];           // 10 TB. Nonces are the same as 1t.

pub trait SeedRNG { fn fill(&mut self, buf: &mut [u8]); }
pub mod hash;
pub mod prng;

#[cfg(test)]
mod tests;
