# Yadacha

## Overview

See [yadacha.com](https://yadacha.com) for a quick start guide.

Yadacha is a symmetric cipher that combines ChaCha20 and very large private keys. All modern crypto rely on unproven assumptions (see ‘[Exponential time hypothesis](https://en.wikipedia.org/wiki/Exponential_time_hypothesis)’ or ‘[Computational hardness assumption](https://en.wikipedia.org/wiki/Computational_hardness_assumption)’). This is often reduced as the '[P versus NP problem](https://en.wikipedia.org/wiki/P_versus_NP_problem)'.

The only provably secure encryption is the [one time pad](https://en.wikipedia.org/wiki/One-time_pad). This is impractical since you need a secure way to transmit the pad, which needs to be as big as the plaintext, so you might as well just transmit the plaintext securely.

Yadacha allows the pad (henceforth called private key) to be smaller than the plaintext, by using a variant of ChaCha20 to expand it in a way that changes with every message.

A quantum computing NP-solver may appear in the future (it might already be here, see 2WQC by Jarek Duda). Such an algorithm will likely break all algorithms with small private keys. Yadacha prevents that simply by using huge private keys that will resist being held in a quantum computer, for a very long time: the largest key is 10 TB (yes, 10 terabytes), meaning you will need a 80 tera-qubits quantum computer just to hold the key.

This won't happen for a while.

Yadacha's smallest key is 16 KB, which is small enough to work even on small embedded boards (tested). To break it would require a quantum computer with more than a hundred thousands qubits.


This won't happen for a while either.

While state hackers might be able to exfiltrate very small keys using extremely subtle means in order to avoid detection, exfiltrating a 16 KB key is a bit more difficult, even more so a 10 TB key.

The standard key sizes are:

- 16 KB for most usage, works fine even on underpowered hardware
- 8 MB keys that can fit your server L3 cache, for more critial communication
- 1 TB keys that can be held in a portable, mobile SSD drive
- 10 TB keys for secure communication between critical locations



## Technical details

Inspired by [ChaCha20](https://cr.yp.to/chacha.html) from [D. J. Bernstein](https://cr.yp.to/djb.html). See also [rfc8439](https://datatracker.ietf.org/doc/html/rfc8439).

Yadacha extends ChaCha20 by applying 64 substitution boxes
at the end of each double-round.
Regular ChaCha20 has a single SAT form for all private keys.
The addition of random substitution boxes makes it impossible
to convert the algorithm into SAT form, since the constraints
between the bits are now dependant on the substitution boxes, which are now the private key: the SAT form therefore changes depending on the key. While adding 64 substitution boxes requires private key sizes of 64\*256 = 16 KB (for the smallest yadacha key size), because some s-boxes are invalid, the real entropy of a single substitution  box is about log_2(256!) ~= 1684 bits instead of 256\*8 = 2048 bits. Therefore, the whole private key has entropy of 64\*1684/8 = 13.2 KB. The effect is similar for larger key sizes.

While applying the substitution boxes only once
would still prevent SAT form translation, applying them at each
double-round ensure they deeply interact with each other.

Why modify ChaCha20 instead of AES256?
ChaCha20 performs better without hardware support,
hence a no-sat ChaCha20 will do better than a
hypothetical a no-sat AES256.

Note that Yadacha isn't currently constant time, so it should not be used without proper consideration regarding potential side channel timing attacks.

## Special properties of yadacha private keys

Any single bit flip will turn a valid private key into an invalid one. For a dual bit flip to pass undetected, the second one needs to happen on a specific bit. Even with the smallest key, dual bit flips will be caught with >99.999% certainty, assuming they are independant of each other. Triple bit flips (along with all odd numbers of bit flips) will be caught, and even (as opposed to odd) bit flips, will be caught with high certainty, assuming they are independant of each other.

A private key invalidated by a single bit flip can be repaired into two different valid keys: you can then test which one is correct. This is left as an excercise for the reader.

## Remarks about the code

Yadacha is provided as a pure Rust no_std library (with no dependencies), with an accompagning cli tool that leverages mmap for large keys (the cli tool has 2 dependencies). The test suite requires the [rug](https://crates.io/crates/rug) crate for the constants specifications.

If you want to dive into the code, start by understanding lib.rs and yadacha16k.rs, then move on to, in order: yadacha8m.rs, yadacha1t.rs, and yadacha10t.rs.

The code is single-threaded, isn't idiomatic Rust code for the moment, but should be fairly easy to follow, especially if you are familiar with ChaCha20.

## Quick example
### Cargo.toml

```rust
[package]
name = "ytest"
version = "0.1.0"
edition = "2021"

[dependencies]
yadacha = "0.0.3"
getrandom = "0.2.10"
```

### main.rs
```rust
use yadacha::*;

struct RandomSource {}
impl yadacha::SeedRNG for RandomSource {
    fn fill(&mut self, buf: &mut [u8]) {
        getrandom::getrandom(buf).unwrap();
        // or rdrand
    }
}

fn main() {
    let mut data: &mut [u8] = &mut [2, 3, 5, 7, 11, 13, 17, 19];
    println!("data (plaintext): {:?}", data);

    let mut rng = RandomSource{}; // to use getrandom
    //let mut rng = prng::new_fixed_yadarng(42); // to use fixed rng
    let mut key_16k: Key16k = [[0u8; 256]; 64];
    yadacha16k::init_key_16k(&mut rng, &mut key_16k);

    let nonce : Nonce16k = yadacha16k::new_nonce_16k(&mut rng);
    let msg_nonce : MsgNonce16k = yadacha16k::new_msg_nonce_16k(&mut rng, data);
    let mut yada = yadacha16k::new_yadacha16k(&key_16k, &nonce, &msg_nonce);

    println!("key_16k (part): {:?}", &key_16k[0][..8]);
    println!("nonce: {:?}", nonce);
    println!("msg_nonce: {:?}", msg_nonce);

    let associated_data = (data.len() as u64).to_le_bytes(); // or something else
    println!("associated_data: {:?}", associated_data);

    yada.init_encode(&associated_data);
    yada.encode(&mut data);
    let tag = yada.finalize();

    // data is encrypted, tag is [u8;64].
    println!("data (ciphertext): {:?}", data);
    println!("tag (part): {:?}", &tag[..8]);

    let mut yada = yadacha16k::new_yadacha16k(&key_16k, &nonce, &msg_nonce);
    yada.init_decode(&associated_data);
    yada.decode(&mut data);
    let valid = yada.validate(tag);
    assert!(valid);

    // data is decrypted
    println!("data (decrypted): {:?}", data);
}
```

### Example outputs with getrandom rng
(yours will differ)

```rust
data (plaintext): [2, 3, 5, 7, 11, 13, 17, 19]
key_16k (part): [23, 122, 130, 212, 72, 85, 52, 134]
nonce: [876659832, 2034512187, 4227600364, 1904335117, 2528694799, 741854543, 3945783584, 3561167336]
msg_nonce: [3767118128, 1500355652]
associated_data: [8, 0, 0, 0, 0, 0, 0, 0]
data (ciphertext): [206, 86, 63, 114, 232, 20, 222, 69]
tag (part): [221, 209, 249, 239, 197, 16, 152, 120]
data (decrypted): [2, 3, 5, 7, 11, 13, 17, 19]

data (plaintext): [2, 3, 5, 7, 11, 13, 17, 19]
key_16k (part): [98, 81, 95, 24, 184, 192, 215, 251]
nonce: [1756477226, 3512108898, 3482418452, 2734284285, 3102698299, 1823011375, 2586904859, 3783255701]
msg_nonce: [216179676, 2814286635]
associated_data: [8, 0, 0, 0, 0, 0, 0, 0]
data (ciphertext): [80, 105, 31, 147, 114, 121, 203, 196]
tag (part): [145, 41, 188, 227, 153, 158, 93, 79]
data (decrypted): [2, 3, 5, 7, 11, 13, 17, 19]

[...]
```

### Output with fixed rng
(should match exactly for v0.0.3, when using prng::new\_fixed\_yadarng(42))

```rust
data (plaintext): [2, 3, 5, 7, 11, 13, 17, 19]
key_16k (part): [218, 254, 24, 241, 6, 43, 167, 152]
nonce: [4063157125, 3856611287, 16257720, 3825573552, 1180332863, 3315114498, 2462000061, 3047591357]
msg_nonce: [2158674, 4156766091]
associated_data: [8, 0, 0, 0, 0, 0, 0, 0]
data (ciphertext): [69, 192, 68, 122, 241, 72, 195, 65]
tag (part): [146, 19, 75, 193, 224, 7, 92, 31]
data (decrypted): [2, 3, 5, 7, 11, 13, 17, 19]
```

## License

Yadacha is licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

### Changelog

- v0.0.3 BREAKING CHANGE - Small adjustment to the cipher, some cleaning up
- v0.0.2 Added missing repository in Cargo.toml
- v0.0.1 Initial release
