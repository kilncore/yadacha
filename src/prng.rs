use crate::*;
use hash::new_yadachash;
use yadacha16k::BufferedRng;

pub struct Yadarng {
    c: u128,
    h: hash::Yadachash,
    i: usize
}
// ----------------------------------------------------------------------------
pub fn new_random_yadarng(rng: &mut dyn SeedRNG) -> Yadarng {
    let mut brng = BufferedRng::new(rng, 16*1);
    let mut r = Yadarng{
        c: brng.take_u128(), h: new_yadachash(), i: 0
    };
    r.rehash();
    r
}
// ----------------------------------------------------------------------------
pub fn new_fixed_yadarng(seed: u128) -> Yadarng {
    let mut r = Yadarng{
        c: seed, h: new_yadachash(), i: 0
    };
    r.rehash();
    r
}
impl Yadarng {
    fn rehash(&mut self) {
        self.h.hash_all(&self.c.to_le_bytes());
    }
}
impl SeedRNG for Yadarng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            *b = self.h.byte_at(self.i);
            self.i += 1;
            if self.i == hash::STATE_SIZE {
                self.c = self.c.wrapping_add(1);
                self.h = new_yadachash();
                self.rehash();
                self.i = 0;
            }
        }
    }
}
