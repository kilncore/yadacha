use crate::*;

type State = [u32; 16];
pub const STATE_SIZE: usize = 64;
pub const KEY_SIZE: usize = 16384;

const ENTRIES_BYTES: usize = 1;
const ENTRIES_COUNT: usize = 1 << (ENTRIES_BYTES * 8);

// e is for encryption, a is for accumulation
// acc and ks allow operation in small chunks
// inited and done flags are for sanity checks
pub struct Yadacha16k<'a> {
    k: &'a Key16k, 
    e: State, a: State, tag: [u8; STATE_SIZE],
    acc: [u8; STATE_SIZE], acc_index: usize,
    ks: [u8; STATE_SIZE], ks_index: usize,
    inited: bool, encoding: bool, done: bool,
}

// same idea as https://en.wikipedia.org/wiki/SHA-2
// first 32 bits of the fractional parts of the square roots of the first 6 primes 2..13
// it's better to double-check them by calculating them ourselves, see tests.rs
pub const CONSTANTS: [u32; 6] =
    [   0x6A09E667, 0xBB67AE85,
        0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C ];

// ----------------------------------------------------------------------------
pub fn new_yadacha16k<'a>(key: &'a Key16k,
                      nonce: &Nonce16k,
                      msg_nonce: &MsgNonce16k) -> Yadacha16k<'a> {
    let mut r = Yadacha16k {
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
fn apply_key(w: u32, key: &Key16k, offset: usize) -> u32 {
    (((key[offset+0][((w >> 24) & 0xff) as usize]) as u32) << 24) |
    (((key[offset+1][((w >> 16) & 0xff) as usize]) as u32) << 16) |
    (((key[offset+2][((w >>  8) & 0xff) as usize]) as u32) <<  8) |
    (((key[offset+3][((w >>  0) & 0xff) as usize]) as u32) <<  0)
}
// ----------------------------------------------------------------------------
fn state_to_u8(state: &State, dst: &mut [u8;STATE_SIZE]) {
    for (chunk, val) in dst.chunks_exact_mut(4).zip(state.iter()) {
        chunk.copy_from_slice(&val.to_le_bytes());
    }
}

// ----------------------------------------------------------------------------
impl Yadacha16k<'_> {
    fn run_rounds(&self, state: &State) -> State {
        let mut res = *state;
        
        for _ in 0..10 {

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
    
            for i in 0..16 {
                res[i] = apply_key(res[i], self.k, i*4);
            }
        }
    
        for (s1, s0) in res.iter_mut().zip(state.iter()) {
            *s1 = s1.wrapping_add(*s0);
        }
    
        res
    }

    fn incr_block_index(&mut self) {
        if self.e[15] == u32::MAX {
            assert!(self.e[14] != u32::MAX);
            self.e[14] += 1;
            self.e[15] = 0;
        } else {
            self.e[15] += 1;
        }
    }

    fn set_block_index(&mut self, pos: u64) {
        self.e[14] = (pos >> 32) as u32;
        self.e[15] = (pos & (u32::MAX as u64)) as u32;
    }

    fn accumulate_byte(&mut self, byte: u8) {
        assert!(self.acc_index < STATE_SIZE);
        self.acc[self.acc_index] = byte;
        self.acc_index += 1;
        if self.acc_index == STATE_SIZE {
            // xor accumulated bytes into state, then run_rounds
            for (a, acc) in self.a.iter_mut().zip(self.acc.chunks_exact(4)) {
                *a ^= u32::from_le_bytes(acc.try_into().unwrap());
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
impl Yadacha for Yadacha16k<'_> {
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
        self.set_block_index(byte_index / state_size);
        let byte_offset = byte_index % state_size;
        state_to_u8(&self.run_rounds(&self.e), &mut self.ks);
        self.ks_index = byte_offset as usize;
        for b in data {
            self.transform_byte(b);
        }
    }
}

// ----------------------------------------------------------------------------
pub fn init_key_16k(rng: &mut dyn SeedRNG, key: &mut Key16k) {
    let mut brng = BufferedRng::new(rng, 16*1024);

    for i in 0..64 {
        let mut set = [0u8; ENTRIES_COUNT];
        for j in 0..ENTRIES_COUNT {
            set[j] = j as u8;
        }

        let mut shift = 0;
        let mut remaining = ENTRIES_COUNT;
        while remaining > 0 {
            let mut choice = brng.take_u8() as usize;
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
                }
            }
        }
    }
}

// ----------------------------------------------------------------------------
pub fn new_nonce_16k(rng: &mut dyn SeedRNG) -> Nonce16k {
    let mut brng = BufferedRng::new(rng, 4*8);

    let mut n: Nonce16k = [0; 8];
    for i in 0..n.len() {
        n[i] = brng.take_u32();
    }
    n
}

// ----------------------------------------------------------------------------
pub fn new_msg_nonce_16k(rng: &mut dyn SeedRNG, msg: &[u8]) -> MsgNonce16k {
    let mut brng = BufferedRng::new(rng, 4*2);

    let mut yadahash = hash::new_yadachash();
    yadahash.hash_all(msg);

    let mut n = yadahash.result_as_msg_nonce_16k();
    for i in 0..n.len() {
        n[i] ^= brng.take_u32();
    }
    n
}

// ----------------------------------------------------------------------------
pub fn validate_key_16k(key: &Key16k) -> bool {
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

// ----------------------------------------------------------------------------
// helper tool, to minimize calls to SeedRNG, and make it easier for rustc to inline
#[cfg(target_pointer_width = "64")]
const RNG_BUFFER_SIZE: usize = 1 << 16;
#[cfg(not(target_pointer_width = "64"))]
const RNG_BUFFER_SIZE: usize = 1 << 8;

pub struct BufferedRng<'a> {
    s: &'a mut dyn SeedRNG,
    r: [u8;RNG_BUFFER_SIZE],
    i: usize, e: usize
}
impl BufferedRng<'_> {
    pub fn new<'a>(rng: &'a mut dyn SeedRNG, limit_size: usize) -> BufferedRng {
        let mut r = BufferedRng{
            s: rng,
            r: [0;RNG_BUFFER_SIZE],
            i: 0,
            e: limit_size
        };
        if r.e == 0 || r.e > RNG_BUFFER_SIZE {
            r.e = RNG_BUFFER_SIZE;
        }
        r.refill();
        r
    }
    #[inline(always)]
    fn refill(&mut self) {
        self.s.fill(&mut self.r[..self.e]);
    }
    #[inline(always)]
    pub fn fill(&mut self, buf: &mut [u8]) {
        let len = buf.len();
        let ne = self.i + len;
        if ne < self.e {
            // fast path
            buf.copy_from_slice(&self.r[self.i..ne]);
            self.i = ne;
            return;
        }
        // slow path
        for b in buf {
            *b = self.r[self.i];
            self.i += 1;
            if self.i == self.e {
                self.refill();
                self.i = 0;
            }
        }
    }
    #[inline(always)]
    pub fn take_u8(&mut self) -> u8 {
        let ne = self.i + 1;
        if ne < self.e {
            // fast path
            let r = self.r[self.i];
            self.i = ne;
            return r;
        }
        // slow path
        let mut buf = [0u8; 1];
        self.fill(&mut buf);
        buf[0]
    }
    #[inline(always)]
    pub fn take_u16(&mut self) -> u16 {
        let ne = self.i + 2;
        if ne < self.e {
            // fast path
            let r = u16::from_le_bytes([self.r[self.i], self.r[self.i+1]]);
            self.i = ne;
            return r;
        }
        // slow path
        let mut buf = [0u8; 2];
        self.fill(&mut buf);
        u16::from_le_bytes(buf)
    }
    #[inline(always)]
    pub fn take_u24(&mut self) -> u32 {
        ((self.take_u8() as u32) << 16) | self.take_u16() as u32
    }
    #[inline(always)]
    pub fn take_u32(&mut self) -> u32 {
        let ne = self.i + 4;
        if ne < self.e {
            // fast path
            let r = u32::from_le_bytes([self.r[self.i], self.r[self.i+1],
                                        self.r[self.i+2], self.r[self.i+3]]);
            self.i = ne;
            return r;
        }
        // slow path
        let mut buf = [0u8; 4];
        self.fill(&mut buf);
        u32::from_le_bytes(buf)
    }
    #[inline(always)]
    pub fn take_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill(&mut buf);
        u64::from_le_bytes(buf)
    }
    #[inline(always)]
    pub fn take_u128(&mut self) -> u128 {
        let mut buf = [0u8; 16];
        self.fill(&mut buf);
        u128::from_le_bytes(buf)
    }
}
