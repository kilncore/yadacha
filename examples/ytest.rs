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
