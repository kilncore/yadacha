use crate::*;

type State = [u32; 16];
pub const STATE_SIZE: usize = 64;

pub struct Yadachash {
    a: State, tag: [u8; STATE_SIZE],
    acc: [u8; STATE_SIZE], acc_index: usize,
    inited: bool, done: bool,
}

pub const CONSTANTS: [u32; 16] =
    [   0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
        0xCBBB9D5D, 0x629A292A, 0x9159015A, 0x152FECD8,
        0x67332667, 0x8EB44A87, 0xDB0C2E0D, 0x47B5481D ];

// ----------------------------------------------------------------------------
pub fn new_yadachash() -> Yadachash {
    let mut r = Yadachash {
        a: [
            CONSTANTS[0], CONSTANTS[1], CONSTANTS[2], CONSTANTS[3],
            CONSTANTS[4], CONSTANTS[5], CONSTANTS[6], CONSTANTS[7],
            CONSTANTS[8], CONSTANTS[9], CONSTANTS[10], CONSTANTS[11],
            CONSTANTS[12], CONSTANTS[13], CONSTANTS[14], CONSTANTS[15]
        ],
        tag: [0;STATE_SIZE],
        acc: [0;STATE_SIZE], acc_index: 0,
        inited: false, done: false
    };
    r.a = r.run_rounds(&r.a);
    r
}

// ----------------------------------------------------------------------------
fn state_to_u8(state: &State, dst: &mut [u8;STATE_SIZE]) {
    for (chunk, val) in dst.chunks_exact_mut(4).zip(state.iter()) {
        chunk.copy_from_slice(&val.to_le_bytes());
    }
}

impl Yadachash {
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

    pub fn init_hash(&mut self) {
        assert!(!self.inited && !self.done);
        self.inited = true;
    }
    pub fn hash(&mut self, data: &[u8]) {
        assert!(self.inited && !self.done);
        for b in data {
            self.accumulate_byte(*b);
        }
    }
    pub fn finalize(&mut self) -> &[u8] {
        assert!(self.inited && !self.done);
        self.done = true;
        while self.acc_index != 0 {
            self.accumulate_byte(0);
        }
        state_to_u8(&self.a, &mut self.tag);
        &self.tag
    }
    pub fn hash_all(&mut self, data: &[u8]) {
        self.init_hash();
        self.hash(data);
        self.finalize();
    }

    pub fn result_as_msg_nonce_16k(&self) -> MsgNonce16k {
        assert!(self.inited && self.done);
        [self.a[0], self.a[1]]
    }
    pub fn result_as_msg_nonce_8m(&self) -> MsgNonce8m {
        assert!(self.inited && self.done);
        [((self.a[0] as u64) << 32) | self.a[1] as u64,
        ((self.a[2] as u64) << 32) | self.a[3] as u64]
    }
    #[cfg(target_pointer_width = "64")]
    pub fn result_as_msg_nonce_1t(&self) -> MsgNonce1t {
        assert!(self.inited && self.done);
        [((self.a[0] as u128) << 96) | ((self.a[1] as u128) << 64) | ((self.a[2] as u128) << 32) | self.a[3] as u128,
        ((self.a[4] as u128) << 96) | ((self.a[5] as u128) << 64) | ((self.a[6] as u128) << 32) | self.a[7] as u128]
    }
    pub fn byte_at(&self, i: usize) -> u8 {
        assert!(self.inited && self.done);
        assert!(i < STATE_SIZE);
        self.tag[i]
    }

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
        }
    
        for (s1, s0) in res.iter_mut().zip(state.iter()) {
            *s1 = s1.wrapping_add(*s0);
        }
    
        res
    }
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

