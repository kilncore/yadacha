use crate::*;
use yadacha16k::BufferedRng;

type State = [u128; 16];
pub const STATE_SIZE: usize = 256;
pub const KEY_SIZE: usize = 1099511627776;

const ENTRIES_BYTES: usize = 4;
pub const ENTRIES_COUNT: usize = 1 << (ENTRIES_BYTES * 8);

pub trait ReadEntry32 { fn read(&mut self, index: usize) -> u32; }
pub struct Yadacha1t<'a> {
    k: &'a Key1t, 
    f: &'a mut dyn ReadEntry32, uf: bool,
    e: State, a: State, tag: [u8; STATE_SIZE],
    acc: [u8; STATE_SIZE], acc_index: usize,
    ks: [u8; STATE_SIZE], ks_index: usize,
    inited: bool, encoding: bool, done: bool,
}

pub const CONSTANTS: [u128; 6] =
    [   140949571415070559626692937523481902398, 249103981505922019304800303939765943177,
         80329770137867282868098132336256454760, 219737784571358085148510647875165364437,
        107741833087981389457187366293593607355, 206058421306879485635369128973983878108 ];

// ----------------------------------------------------------------------------
pub fn new_yadacha1t<'a> (key: &'a Key1t, file: &'a mut dyn ReadEntry32, use_file: bool,
                      nonce: &Nonce1t,
                      msg_nonce: &MsgNonce1t) -> Yadacha1t<'a> {
    let mut r = Yadacha1t {
        k: key, f: file, uf: use_file,
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
    state_to_u8(&run_rounds(&r.e, r.k, r.f, r.uf), &mut r.ks);
    r.a = run_rounds(&r.a, r.k, r.f, r.uf);
    r
}
// ----------------------------------------------------------------------------
#[inline(always)]
fn apply_key(w: u128, key: &Key1t, offset: usize) -> u128 {
    (((key[offset+0][((w >> 96) & 0xffffffff) as usize]) as u128) << 96) |
    (((key[offset+1][((w >> 64) & 0xffffffff) as usize]) as u128) << 64) |
    (((key[offset+2][((w >> 32) & 0xffffffff) as usize]) as u128) << 32) |
    (((key[offset+3][((w >>  0) & 0xffffffff) as usize]) as u128) <<  0)
}
#[inline(always)]
fn apply_key_file(w: u128, key: &mut dyn ReadEntry32, offset: usize) -> u128 {
    let k0 = key.read((offset+0)*ENTRIES_COUNT + ((w >> 96) & 0xffffffff) as usize);
    let k1 = key.read((offset+1)*ENTRIES_COUNT + ((w >> 64) & 0xffffffff) as usize);
    let k2 = key.read((offset+2)*ENTRIES_COUNT + ((w >> 32) & 0xffffffff) as usize);
    let k3 = key.read((offset+3)*ENTRIES_COUNT + ((w >>  0) & 0xffffffff) as usize);
    ((k0 as u128) << 96) |
    ((k1 as u128) << 64) |
    ((k2 as u128) << 32) |
    ((k3 as u128) <<  0)
}
// ----------------------------------------------------------------------------
fn state_to_u8(state: &State, dst: &mut [u8;STATE_SIZE]) {
    for (chunk, val) in dst.chunks_exact_mut(16).zip(state.iter()) {
        chunk.copy_from_slice(&val.to_le_bytes());
    }
}

fn run_rounds(state: &State, k: &Key1t, f: &mut dyn ReadEntry32, use_file: bool) -> State {
    let mut res = *state;
    let mut round0_state = [0u128; 16];
    
    for round in 0..10 {

        for _ in 0..4 {
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
            if use_file {
                res[i] = apply_key_file(res[i], f, i*4);
            } else {
                res[i] = apply_key(res[i], k, i*4);
            }
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

// ----------------------------------------------------------------------------
impl Yadacha1t<'_> {
    

    fn incr_block_index(&mut self) {
        if self.e[15] == u128::MAX {
            assert!(self.e[14] != u128::MAX);
            self.e[14] += 1;
            self.e[15] = 0;
        } else {
            self.e[15] += 1;
        }
    }

    fn set_block_index(&mut self, pos: u128) {
        //pos: u256, eventually
        //self.e[14] = (pos >> 128) as u128;
        //self.e[15] = (pos & u128::MAX) as u128;
        self.e[14] = 0;
        self.e[15] = pos;
    }

    fn accumulate_byte(&mut self, byte: u8) {
        assert!(self.acc_index < STATE_SIZE);
        self.acc[self.acc_index] = byte;
        self.acc_index += 1;
        if self.acc_index == STATE_SIZE {
            // xor accumulated bytes into state, then run_rounds
            for (a, acc) in self.a.iter_mut().zip(self.acc.chunks_exact(16)) {
                *a ^= u128::from_le_bytes(acc.try_into().unwrap());
            }
            self.a = run_rounds(&self.a, self.k, self.f, self.uf);
            self.acc_index = 0;
        }
    }

    fn transform_byte(&mut self, byte: &mut u8) {
        assert!(self.ks_index < STATE_SIZE);
        *byte ^= self.ks[self.ks_index];
        self.ks_index += 1;
        if self.ks_index == STATE_SIZE {
            self.incr_block_index();
            state_to_u8(&run_rounds(&self.e, self.k, self.f, self.uf), &mut self.ks);
            self.ks_index = 0;
        }
    }
}

// ----------------------------------------------------------------------------
impl Yadacha for Yadacha1t<'_> {
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
        state_to_u8(&run_rounds(&self.e, self.k, self.f, self.uf), &mut self.ks);
        self.ks_index = byte_offset as usize;
        for b in data {
            self.transform_byte(b);
        }
    }
}
// ----------------------------------------------------------------------------
pub fn init_subkey_1t(brng: &mut BufferedRng, subkey: &mut [u32; 1 << 32],
                    set: &mut [u32; ENTRIES_COUNT]) {
    for j in 0..ENTRIES_COUNT {
        set[j] = j as u32;
    }

    let mut shift = 0;
    let mut remaining = ENTRIES_COUNT;
    let mut seed_bytes = ENTRIES_BYTES;
    while remaining > 0 {
        let mut choice: usize;
        match seed_bytes {
            1 => { choice = brng.take_u8() as usize; },
            2 => { choice = brng.take_u16() as usize; },
            3 => { choice = brng.take_u24() as usize; },
            4 => { choice = brng.take_u32() as usize; },
            _ => { unreachable!(); }
        }
        choice >>= shift;
        if choice < remaining {
            subkey[ENTRIES_COUNT-remaining] = set[choice];
            remaining -= 1;
            set[choice] = set[remaining];
            if remaining == 1 {
                subkey[ENTRIES_COUNT-remaining] = set[0];
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
// ----------------------------------------------------------------------------
pub fn init_key_1t(rng: &mut dyn SeedRNG, key: &mut Key1t,
                    set: &mut [u32; ENTRIES_COUNT],
                    seen: &mut [bool; ENTRIES_COUNT]) {
    let mut brng = BufferedRng::new(rng, 0);
    
    for i in 0..64 {
        let subkey = &mut key[i];
        init_subkey_1t(&mut brng, subkey, set);
        assert!(validate_subkey_1t(&subkey, seen));
    }
}

// ----------------------------------------------------------------------------
pub fn new_nonce_1t(rng: &mut dyn SeedRNG) -> Nonce1t {
    let mut brng = BufferedRng::new(rng, 16*8);

    let mut n: Nonce1t = [0; 8];
    for i in 0..n.len() {
        n[i] = brng.take_u128();
    }
    n
}

// ----------------------------------------------------------------------------
pub fn new_msg_nonce_1t(rng: &mut dyn SeedRNG, msg: &[u8]) -> MsgNonce1t {
    let mut brng = BufferedRng::new(rng, 16*2);

    let mut yadahash = hash::new_yadachash();
    yadahash.hash_all(msg);

    let mut n = yadahash.result_as_msg_nonce_1t();
    for i in 0..n.len() {
        n[i] ^= brng.take_u128();
    }
    n
}

// ----------------------------------------------------------------------------
pub fn validate_subkey_1t(subkey: &[u32; 1 << 32], seen: &mut [bool; ENTRIES_COUNT]) -> bool {
    //let sub_key = &key[i];
    //let mut seen: [bool; ENTRIES_COUNT] = [false; ENTRIES_COUNT];
    for i in 0..ENTRIES_COUNT {
        seen[i] = false;
    }
    for i in 0..ENTRIES_COUNT {
        let index = subkey[i] as usize;
        if seen[index] {
            //panic!("validate_key failed, already seen {} in sbox {:?}", index, sbox);
            return false;
        }
        seen[index] = true;
    }
    true
}

// ----------------------------------------------------------------------------
pub fn validate_key_1t(key: &Key1t, seen: &mut [bool; ENTRIES_COUNT]) -> bool {
    for i in 0..64 {
        let subkey = &key[i];
        if !validate_subkey_1t(subkey, seen) {
            return false;
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
