use crate::*;
use rug::Integer;

extern crate std;
use std::boxed::Box;
use std::alloc::{alloc, Layout};

// https://en.wikipedia.org/wiki/Integer_square_root
fn integer_sqrt(n: Integer) -> Integer {
    if n < 2 {
        return n;
    }
    let small_cand: Integer = integer_sqrt(n.clone() >> 2) << 1;
    let large_cand: Integer = small_cand.clone() + 1;
    if large_cand.clone().square() > n {
        return small_cand;
    } else {
        return large_cand;
    }
}

fn sqrt_frac_part(n: u128) -> u128 {
    integer_sqrt(Integer::from(n) << 256).to_u128_wrapping()
}

#[test]
fn check_csts() {
    assert_eq!(sqrt_frac_part(2), yadacha1t::CONSTANTS[0]);
    assert_eq!(sqrt_frac_part(3), yadacha1t::CONSTANTS[1]);
    assert_eq!(sqrt_frac_part(5), yadacha1t::CONSTANTS[2]);
    assert_eq!(sqrt_frac_part(7), yadacha1t::CONSTANTS[3]);
    assert_eq!(sqrt_frac_part(11), yadacha1t::CONSTANTS[4]);
    assert_eq!(sqrt_frac_part(13), yadacha1t::CONSTANTS[5]);

    assert_eq!(yadacha1t::CONSTANTS[0] >> 64, yadacha8m::CONSTANTS[0] as u128);
    assert_eq!(yadacha1t::CONSTANTS[1] >> 64, yadacha8m::CONSTANTS[1] as u128);
    assert_eq!(yadacha1t::CONSTANTS[2] >> 64, yadacha8m::CONSTANTS[2] as u128);
    assert_eq!(yadacha1t::CONSTANTS[3] >> 64, yadacha8m::CONSTANTS[3] as u128);
    assert_eq!(yadacha1t::CONSTANTS[4] >> 64, yadacha8m::CONSTANTS[4] as u128);
    assert_eq!(yadacha1t::CONSTANTS[5] >> 64, yadacha8m::CONSTANTS[5] as u128);

    assert_eq!(yadacha1t::CONSTANTS[0] >> 96, yadacha16k::CONSTANTS[0] as u128);
    assert_eq!(yadacha1t::CONSTANTS[1] >> 96, yadacha16k::CONSTANTS[1] as u128);
    assert_eq!(yadacha1t::CONSTANTS[2] >> 96, yadacha16k::CONSTANTS[2] as u128);
    assert_eq!(yadacha1t::CONSTANTS[3] >> 96, yadacha16k::CONSTANTS[3] as u128);
    assert_eq!(yadacha1t::CONSTANTS[4] >> 96, yadacha16k::CONSTANTS[4] as u128);
    assert_eq!(yadacha1t::CONSTANTS[5] >> 96, yadacha16k::CONSTANTS[5] as u128);

    assert_eq!(yadacha10t::CONSTANTS[0], yadacha1t::CONSTANTS[0]);
    assert_eq!(yadacha10t::CONSTANTS[1], yadacha1t::CONSTANTS[1]);
    assert_eq!(yadacha10t::CONSTANTS[2], yadacha1t::CONSTANTS[2]);
    assert_eq!(yadacha10t::CONSTANTS[3], yadacha1t::CONSTANTS[3]);
    assert_eq!(yadacha10t::CONSTANTS[4], yadacha1t::CONSTANTS[4]);
    assert_eq!(yadacha10t::CONSTANTS[5], yadacha1t::CONSTANTS[5]);

    assert_eq!(yadacha1t::CONSTANTS[0] >> 96, hash::CONSTANTS[0] as u128);
    assert_eq!(yadacha1t::CONSTANTS[1] >> 96, hash::CONSTANTS[1] as u128);
    assert_eq!(yadacha1t::CONSTANTS[2] >> 96, hash::CONSTANTS[2] as u128);
    assert_eq!(yadacha1t::CONSTANTS[3] >> 96, hash::CONSTANTS[3] as u128);
    assert_eq!(yadacha1t::CONSTANTS[4] >> 96, hash::CONSTANTS[4] as u128);
    assert_eq!(yadacha1t::CONSTANTS[5] >> 96, hash::CONSTANTS[5] as u128);
    assert_eq!(sqrt_frac_part(17) >> 96, hash::CONSTANTS[6] as u128);
    assert_eq!(sqrt_frac_part(19) >> 96, hash::CONSTANTS[7] as u128);
    assert_eq!(sqrt_frac_part(23) >> 96, hash::CONSTANTS[8] as u128);
    assert_eq!(sqrt_frac_part(29) >> 96, hash::CONSTANTS[9] as u128);
    assert_eq!(sqrt_frac_part(31) >> 96, hash::CONSTANTS[10] as u128);
    assert_eq!(sqrt_frac_part(37) >> 96, hash::CONSTANTS[11] as u128);
    assert_eq!(sqrt_frac_part(41) >> 96, hash::CONSTANTS[12] as u128);
    assert_eq!(sqrt_frac_part(43) >> 96, hash::CONSTANTS[13] as u128);
    assert_eq!(sqrt_frac_part(47) >> 96, hash::CONSTANTS[14] as u128);
    assert_eq!(sqrt_frac_part(53) >> 96, hash::CONSTANTS[15] as u128);
}

fn alloc_key_16k() -> Box<Key16k> {
    let key: Box<Key16k>;
    unsafe {
        let ptr = alloc(Layout::new::<Key16k>()) as *mut Key16k;
        key = Box::from_raw(ptr);
    }
    key
}

fn alloc_key_8m() -> Box<Key8m> {
    let key: Box<Key8m>;
    unsafe {
        let ptr = alloc(Layout::new::<Key8m>()) as *mut Key8m;
        key = Box::from_raw(ptr);
    }
    key
}

fn alloc_temp_1t_set() -> Box<[u32; yadacha1t::ENTRIES_COUNT]> {
    let set: Box<[u32; yadacha1t::ENTRIES_COUNT]>;
    unsafe {
        let ptr = alloc(Layout::new::<[u32; yadacha1t::ENTRIES_COUNT]>()) as *mut [u32; yadacha1t::ENTRIES_COUNT];
        set = Box::from_raw(ptr);
    }
    set
}

fn alloc_temp_1t_seen() -> Box<[bool; yadacha1t::ENTRIES_COUNT]> {
    let seen: Box<[bool; yadacha1t::ENTRIES_COUNT]>;
    unsafe {
        let ptr = alloc(Layout::new::<[bool; yadacha1t::ENTRIES_COUNT]>()) as *mut [bool; yadacha1t::ENTRIES_COUNT];
        seen = Box::from_raw(ptr);
    }
    seen
}


#[test]
fn check_16k() {
    let associated_data = sqrt_frac_part(59).to_le_bytes();
    let ori_data = sqrt_frac_part(61).to_le_bytes();
    let mut rng = prng::new_fixed_yadarng(sqrt_frac_part(67));

    let mut key_16k = alloc_key_16k();
    yadacha16k::init_key_16k(&mut rng, &mut key_16k);
    assert!(yadacha16k::validate_key_16k(&key_16k));

    let mut data = ori_data.clone();
    let nonce : Nonce16k = yadacha16k::new_nonce_16k(&mut rng);
    let msg_nonce : MsgNonce16k = yadacha16k::new_msg_nonce_16k(&mut rng, &data);
    let mut yada = yadacha16k::new_yadacha16k(&key_16k, &nonce, &msg_nonce);
    yada.init_encode(&associated_data);
    yada.encode(&mut data);
    let tag = yada.finalize();

    assert_eq!(key_16k[0][..16], [147, 248, 134, 190, 116, 121, 4, 162, 104, 222, 8, 171, 192, 155, 38, 218]);
    assert_eq!(nonce, [2554256684, 3302170332, 773130132, 582558227, 984784718, 3424706555, 2562883522, 26068239]);
    assert_eq!(msg_nonce, [4060840281, 1371797751]);
    assert_eq!(data, [91, 75, 160, 15, 182, 25, 15, 37, 163, 174, 195, 170, 246, 240, 6, 239]);
    assert_eq!(tag, [147, 106, 17, 133, 38, 93, 227, 75, 215, 15, 131, 18, 138, 16, 238, 31, 115, 151, 216, 27, 136, 226, 151, 197, 5, 18, 65, 94, 49, 242, 68, 187, 253, 42, 131, 162, 189, 67, 223, 194, 58, 236, 130, 99, 13, 159, 2, 128, 140, 181, 165, 81, 21, 247, 133, 148, 191, 163, 159, 76, 15, 36, 196, 193]);

    let mut yada = yadacha16k::new_yadacha16k(&key_16k, &nonce, &msg_nonce);
    yada.init_decode(&associated_data);
    yada.decode(&mut data);
    let valid = yada.validate(&tag);
    assert!(valid);

    assert_eq!(data, ori_data);
}

#[test]
fn check_8m() {
    let associated_data = sqrt_frac_part(59).to_le_bytes();
    let ori_data = sqrt_frac_part(61).to_le_bytes();
    let mut rng = prng::new_fixed_yadarng(sqrt_frac_part(67));

    let mut key_8m = alloc_key_8m();
    yadacha8m::init_key_8m(&mut rng, &mut key_8m);
    assert!(yadacha8m::validate_key_8m(&key_8m));

    let mut data = ori_data.clone();
    let nonce : Nonce8m = yadacha8m::new_nonce_8m(&mut rng);
    let msg_nonce : MsgNonce8m = yadacha8m::new_msg_nonce_8m(&mut rng, &data);
    let mut yada = yadacha8m::new_yadacha8m(&key_8m, &nonce, &msg_nonce);
    yada.init_encode(&associated_data);
    yada.encode(&mut data);
    let tag = yada.finalize();

    assert_eq!(key_8m[0][..16], [63635, 48774, 31092, 41476, 56936, 43784, 49400, 9883, 17882, 63124, 12322, 27495, 11861, 968, 64720, 14618]);
    assert_eq!(nonce, [16735576189361918649, 2898955267481651275, 16049008267602703069, 9244850915759370945, 11777281011042286855, 2970257613299196505, 6108691448868560640, 1342205956880350260]);
    assert_eq!(msg_nonce, [186084849978357342, 13031428407824554078]);
    assert_eq!(data, [89, 102, 47, 152, 10, 247, 172, 79, 100, 244, 60, 123, 105, 54, 214, 89]);
    assert_eq!(tag, [207, 130, 223, 237, 120, 72, 164, 63, 104, 68, 43, 182, 225, 148, 237, 137, 164, 73, 146, 234, 207, 6, 34, 16, 16, 254, 163, 174, 82, 126, 97, 146, 53, 185, 113, 29, 139, 139, 128, 147, 6, 239, 25, 37, 253, 73, 5, 36, 160, 9, 206, 239, 177, 235, 141, 84, 163, 100, 58, 121, 167, 176, 6, 115, 191, 215, 111, 64, 1, 247, 190, 212, 164, 146, 250, 211, 96, 124, 186, 98, 172, 74, 141, 0, 163, 14, 155, 17, 114, 46, 229, 65, 217, 240, 30, 57, 136, 23, 251, 59, 71, 133, 161, 13, 169, 89, 235, 245, 106, 110, 34, 50, 161, 153, 158, 35, 31, 98, 198, 23, 110, 155, 227, 142, 44, 141, 58, 164]);

    let mut yada = yadacha8m::new_yadacha8m(&key_8m, &nonce, &msg_nonce);
    yada.init_decode(&associated_data);
    yada.decode(&mut data);
    let valid = yada.validate(&tag);
    assert!(valid);

    assert_eq!(data, ori_data);
}

#[test]
#[ignore]
fn check_keygen_16k() {
    let mut rng = prng::new_fixed_yadarng(sqrt_frac_part(88));
    let mut key_16k = alloc_key_16k();
    for _ in 0..300000 {
        yadacha16k::init_key_16k(&mut rng, &mut key_16k);
        assert!(yadacha16k::validate_key_16k(&key_16k));
    }
}

#[test]
#[ignore]
fn check_keygen_8m() {
    let mut rng = prng::new_fixed_yadarng(sqrt_frac_part(75));
    let mut key_8m = alloc_key_8m();
    for _ in 0..1000 {
        yadacha8m::init_key_8m(&mut rng, &mut key_8m);
        assert!(yadacha8m::validate_key_8m(&key_8m));
    }
    
}

#[test]
#[ignore]
fn check_keygen_subkey_1t() {
    let mut rng = prng::new_fixed_yadarng(sqrt_frac_part(57));
    let mut brng = yadacha16k::BufferedRng::new(&mut rng, 0);
    let mut subkey_1t = alloc_temp_1t_set();
    let mut temp_set = alloc_temp_1t_set();
    let mut temp_seen = alloc_temp_1t_seen();
    for _ in 0..1 {
        yadacha1t::init_subkey_1t(&mut brng, &mut subkey_1t, &mut temp_set);
        assert!(yadacha1t::validate_subkey_1t(&subkey_1t, &mut temp_seen));
    }
}

// #[cfg(target_pointer_width = "64")]
// #[test]
// fn check_1t() {
// 
// }

// #[cfg(target_pointer_width = "64")]
// #[test]
// fn check_10t() {
//
// }

