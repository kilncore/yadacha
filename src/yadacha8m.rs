use crate::*;
use yadacha16k::BufferedRng;

type State = [u64; 16];
pub const STATE_SIZE: usize = 128;
pub const KEY_SIZE: usize = 8388608;

const ENTRIES_BYTES: usize = 2;
const ENTRIES_COUNT: usize = 1 << (ENTRIES_BYTES * 8);

pub struct Yadacha8m<'a> {
    k: &'a Key8m, 
    e: State, a: State, tag: [u8; STATE_SIZE],
    acc: [u8; STATE_SIZE], acc_index: usize,
    ks: [u8; STATE_SIZE], ks_index: usize,
    inited: bool, encoding: bool, done: bool,
}

pub const CONSTANTS: [u64; 6] =
    [   0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
        0x510E527FADE682D1, 0x9B05688C2B3E6C1F ];

// ----------------------------------------------------------------------------
pub fn new_yadacha8m<'a> (key: &'a Key8m,
                      nonce: &Nonce8m,
                      msg_nonce: &MsgNonce8m) -> Yadacha8m<'a> {
    let mut r = Yadacha8m {
        k: key,
        e: [
            CONSTANTS[0], CONSTANTS[1], CONSTANTS[2], CONSTANTS[3],
            nonce[0], nonce[1], nonce[2], nonce[3], 
            nonce[4], nonce[5], nonce[6], nonce[7], 
            msg_nonce[0], msg_nonce[1], 0, 0 // counter
        ],
        a: [
            CONSTANTS[0], CONSTANTS[1], CONSTANTS[2], CONSTANTS[3],
            nonce[0], nonce[1], nonce[2], nonce[3], 
            nonce[4], nonce[5], nonce[6], nonce[7], 
            msg_nonce[0], msg_nonce[1], CONSTANTS[4], CONSTANTS[5]
        ],
        tag: [0;STATE_SIZE],
        ks: [0;STATE_SIZE], ks_index: 0,
        acc: [0;STATE_SIZE], acc_index: 0,
        inited: false, encoding: false, done: false
    };
    state_to_u8(&r.run_rounds(&r.e), &mut r.ks);
    r.a = r.run_rounds(&r.a);
    r
}
// ----------------------------------------------------------------------------
#[inline(always)]
fn apply_key(w: u64, key: &Key8m, offset: usize) -> u64 {
    (((key[offset+0][((w >> 48) & 0xffff) as usize]) as u64) << 48) |
    (((key[offset+1][((w >> 32) & 0xffff) as usize]) as u64) << 32) |
    (((key[offset+2][((w >> 16) & 0xffff) as usize]) as u64) << 16) |
    (((key[offset+3][((w >>  0) & 0xffff) as usize]) as u64) <<  0)
}
// ----------------------------------------------------------------------------
fn state_to_u8(state: &State, dst: &mut [u8;STATE_SIZE]) {
    for (chunk, val) in dst.chunks_exact_mut(8).zip(state.iter()) {
        chunk.copy_from_slice(&val.to_le_bytes());
    }
}

// ----------------------------------------------------------------------------
impl Yadacha8m<'_> {
    fn run_rounds(&self, state: &State) -> State {
        let mut res = *state;
        let mut round0_state = [0u64; 16];
        
        for round in 0..10 {

            for _ in 0..2 {
                // column rounds
                quarter_round(0, 4, 8, 12, &mut res);
                quarter_round(1, 5, 9, 13, &mut res);
                quarter_round(2, 6, 10, 14, &mut res);
                quarter_round(3, 7, 11, 15, &mut res);

                // diagonal rounds
                quarter_round(0, 5, 10, 15, &mut res);
                quarter_round(1, 6, 11, 12, &mut res);
                quarter_round(2, 7, 8, 13, &mut res);
                quarter_round(3, 4, 9, 14, &mut res);
            }
    
            for i in 0..16 {
                res[i] = apply_key(res[i], &self.k, i*4);
            }

            if round == 0 {
                round0_state = res;
            }
        }
    
        for (s1, s0) in res.iter_mut().zip((&round0_state).iter()) {
            *s1 = s1.wrapping_add(*s0);
        }
    
        res
    }

    fn incr_block_index(&mut self) {
        if self.e[15] == u64::MAX {
            assert!(self.e[14] != u64::MAX);
            self.e[14] += 1;
            self.e[15] = 0;
        } else {
            self.e[15] += 1;
        }
    }

    fn set_block_index(&mut self, pos: u128) {
        self.e[14] = (pos >> 64) as u64;
        self.e[15] = (pos & (u64::MAX as u128)) as u64;
    }

    fn accumulate_byte(&mut self, byte: u8) {
        assert!(self.acc_index < STATE_SIZE);
        self.acc[self.acc_index] = byte;
        self.acc_index += 1;
        if self.acc_index == STATE_SIZE {
            // xor accumulated bytes into state, then run_rounds
            for (a, acc) in self.a.iter_mut().zip(self.acc.chunks_exact(8)) {
                *a ^= u64::from_le_bytes(acc.try_into().unwrap());
            }
            self.a = self.run_rounds(&self.a);
            self.acc_index = 0;
        }
    }

    fn transform_byte(&mut self, byte: &mut u8) {
        assert!(self.ks_index < STATE_SIZE);
        *byte ^= self.ks[self.ks_index];
        self.ks_index += 1;
        if self.ks_index == STATE_SIZE {
            self.incr_block_index();
            state_to_u8(&self.run_rounds(&self.e), &mut self.ks);
            self.ks_index = 0;
        }
    }
}

// ----------------------------------------------------------------------------
impl Yadacha for Yadacha8m<'_> {
    fn init_encode(&mut self, associated_data: &[u8]) {
        assert!(!self.inited && !self.done);
        self.inited = true; self.encoding = true;
        for b in associated_data {
            self.accumulate_byte(*b);
        }
    }
    fn encode(&mut self, data: &mut [u8]) {
        assert!(self.inited && self.encoding && !self.done);
        for b in data {
            self.accumulate_byte(*b);
            self.transform_byte(b);
        }
    }
    fn finalize(&mut self) -> &[u8] {
        assert!(self.inited && self.encoding && !self.done);
        self.done = true;
        while self.acc_index != 0 {
            self.accumulate_byte(0);
        }
        state_to_u8(&self.a, &mut self.tag);
        &self.tag
    }
    
    fn init_decode(&mut self, associated_data: &[u8]) {
        assert!(!self.inited && !self.done);
        self.inited = true;
        for b in associated_data {
            self.accumulate_byte(*b);
        }
    }
    fn decode(&mut self, data: &mut [u8]) {
        assert!(self.inited && !self.encoding && !self.done);
        for b in data {
            self.transform_byte(b);
            self.accumulate_byte(*b);
        }
    }
    fn validate(&mut self, tag: &[u8]) -> bool {
        assert!(self.inited && !self.encoding && !self.done);
        self.done = true;
        while self.acc_index != 0 {
            self.accumulate_byte(0);
        }
        state_to_u8(&self.a, &mut self.tag);
        tag == self.tag
    }
    
    fn seek_and_decode(&mut self, byte_index: u64, data: &mut [u8]) {
        assert!(!self.inited && !self.encoding && !self.done);
        let state_size = STATE_SIZE as u64;
        self.set_block_index((byte_index / state_size) as u128);
        let byte_offset = byte_index % state_size;
        state_to_u8(&self.run_rounds(&self.e), &mut self.ks);
        self.ks_index = byte_offset as usize;
        for b in data {
            self.transform_byte(b);
        }
    }
}

// ----------------------------------------------------------------------------
pub fn init_key_8m(rng: &mut dyn SeedRNG, key: &mut Key8m) {
    let mut brng = BufferedRng::new(rng, 0);

    for i in 0..64 {
        let mut set = [0u16; ENTRIES_COUNT];
        for j in 0..ENTRIES_COUNT {
            set[j] = j as u16;
        }

        let mut shift = 0;
        let mut remaining = ENTRIES_COUNT;
        let mut seed_bytes = ENTRIES_BYTES;
        while remaining > 0 {
            let mut choice: usize;
            match seed_bytes {
                1 => { choice = brng.take_u8() as usize; },
                2 => { choice = brng.take_u16() as usize; },
                _ => { unreachable!(); }
            }
            choice >>= shift;
            if choice < remaining {
                key[i][ENTRIES_COUNT-remaining] = set[choice];
                remaining -= 1;
                set[choice] = set[remaining];
                if remaining == 1 {
                    key[i][ENTRIES_COUNT-remaining] = set[0];
                    remaining = 0;
                }
                else if remaining.count_ones() == 1 {
                    shift += 1;
                    if shift == 8 {
                        seed_bytes -= 1;
                        shift  = 0;
                    }
                }
            }
        }
    }
}

// ----------------------------------------------------------------------------
pub fn new_nonce_8m(rng: &mut dyn SeedRNG) -> Nonce8m {
    let mut brng = BufferedRng::new(rng, 8*8);

    let mut n: Nonce8m = [0; 8];
    for i in 0..n.len() {
        n[i] = brng.take_u64();
    }
    n
}

// ----------------------------------------------------------------------------
pub fn new_msg_nonce_8m(rng: &mut dyn SeedRNG, msg: &[u8]) -> MsgNonce8m {
    let mut brng = BufferedRng::new(rng, 8*2);

    let mut yadahash = hash::new_yadachash();
    yadahash.hash_all(msg);

    let mut n = yadahash.result_as_msg_nonce_8m();
    for i in 0..n.len() {
        n[i] ^= brng.take_u64();
    }
    n
}

// ----------------------------------------------------------------------------
pub fn validate_key_8m(key: &Key8m) -> bool {
    for i in 0..64 {
        let sub_key = &key[i];
        let mut seen: [bool; ENTRIES_COUNT] = [false; ENTRIES_COUNT];
        for i in 0..ENTRIES_COUNT {
            let index = sub_key[i] as usize;
            if seen[index] {
                //panic!("validate_key failed, already seen {} in sbox {:?}", index, sbox);
                return false;
            }
            seen[index] = true;
        }
    }
    true
}

// ----------------------------------------------------------------------------
// The ChaCha20 quarter round function
#[inline(always)]
fn quarter_round(a: usize, b: usize, c: usize, d: usize,
                 state: &mut State) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}
