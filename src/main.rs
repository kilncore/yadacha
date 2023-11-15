// Run using: cargo run --bin yadacha --features="build-binary"

use yadacha::*;

use std::fs::File;
use std::boxed::Box;
use std::alloc::{alloc, Layout};
use std::io::prelude::*;
use memmap::{Mmap, MmapMut};

struct RandomSource {}
impl yadacha::SeedRNG for RandomSource {
    fn fill(&mut self, buf: &mut [u8]) {
        getrandom::getrandom(buf).unwrap();
    }
}
struct IntFile<'a> {
    f: &'a mut std::fs::File
}
impl yadacha1t::ReadEntry32 for IntFile<'_> {
    fn read(&mut self, index: usize) -> u32 {
        self.f.seek(std::io::SeekFrom::Start((index * 4) as u64)).unwrap();
        let mut buf: [u8;4] = [0;4];
        self.f.read(&mut buf).unwrap();
        u32::from_le_bytes(buf)
    }
}

fn print_usage_and_exit() {
    println!("Usage: yadacha [verb] [params]\n");
    println!("       yadacha generate_key_16k out_key_file");
    println!("       yadacha generate_key_8m out_key_file");
    println!("       yadacha generate_key_1t out_key_file");
    println!("       yadacha generate_key_10t out_key_file\n");
    println!("       yadacha validate_key in_key_file\n");
    println!("       yadacha encrypt in_key_file in_data_file out_data_file");
    println!("       yadacha decrypt in_key_file in_data_file out_data_file");
    std::process::exit(1);
}

fn safe_read(reader: &mut dyn std::io::Read, buf: &mut [u8]) -> usize {
    loop {
        match reader.read(buf) {
            Ok(n) => {
                return n;
            },
            Err(e) => {
                match e.kind() {
                    std::io::ErrorKind::Interrupted => {
                        // try again
                    },
                    _ => {
                        println!("infile i/o error while reading {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }
    }
}

fn safe_read_u32(reader: &mut dyn std::io::Read) -> u32 {
    let mut buf: [u8;4] = [0; 4];
    if safe_read(reader, &mut buf) != 4 {
        println!("missing data");
        std::process::exit(1);
    }
    u32::from_le_bytes(buf)
}

fn safe_read_u64(reader: &mut dyn std::io::Read) -> u64 {
    let mut buf: [u8;8] = [0; 8];
    if safe_read(reader, &mut buf) != 8 {
        println!("missing data");
        std::process::exit(1);
    }
    u64::from_le_bytes(buf)
}

fn safe_read_u128(reader: &mut dyn std::io::Read) -> u128 {
    let mut buf: [u8;16] = [0; 16];
    if safe_read(reader, &mut buf) != 16 {
        println!("missing data");
        std::process::exit(1);
    }
    u128::from_le_bytes(buf)
}

fn safe_write(writer: &mut dyn std::io::Write, buf: &[u8]) {
    match writer.write_all(buf) {
        Ok(()) => { },
        Err(e) => {
            println!("infile i/o error while writing {}", e);
            std::process::exit(1);
        }
    }
}

fn write_key_16k(key: &yadacha::Key16k, file: &mut File) {
    for t in 0..64 {
        for e in 0..(1<<8) {
            safe_write(file, &key[t][e].to_le_bytes());
        }
    }
}

fn write_key_8m(key: &yadacha::Key8m, file: &mut File) {
    for t in 0..64 {
        for e in 0..(1<<16) {
            safe_write(file, &key[t][e].to_le_bytes());
        }
    }
}

fn alloc_key_16k() -> Box<Key16k> {
    let key: Box<Key16k>;
    unsafe {
        let ptr = alloc(Layout::new::<Key16k>()) as *mut Key16k;
        key = Box::from_raw(ptr);
    }
    key
}

fn load_key_16k(file: &mut File) -> Box<Key16k> {
    let mut key: Box<Key16k> = alloc_key_16k();
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    if data.len() != (1 * (1<<8) * 64) {
        println!("bad key size {}", data.len());
        std::process::exit(1);
    }
    for t in 0..64 {
        for e in 0..(1<<8) {
            let i = t*(1<<8)+e;
            let v = u8::from_le_bytes(data[i..i+1].try_into().unwrap());
            key[t][e] = v;
        }
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

fn load_key_8m(file: &mut File) -> Box<Key8m> {
    let mut key: Box<Key8m> = alloc_key_8m();
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    if data.len() != (2 * (1<<16) * 64) {
        println!("bad key size {}", data.len());
        std::process::exit(1);
    }
    for t in 0..64 {
        for e in 0..(1<<16) {
            let i = (t*(1<<16)+e)*2;
            let v = u16::from_le_bytes(data[i..i+2].try_into().unwrap());
            key[t][e] = v;
        }
    }
    key
}

fn mmap_as_mut_key_1t(mmap: &MmapMut) -> &mut Key1t {
    unsafe {
        let ptr = mmap.as_ptr() as *mut Key1t;
        ptr.as_mut().unwrap()
    }
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

fn mmap_as_ref_key_1t(mmap: &Mmap) -> &Key1t {
    unsafe {
        let ptr = mmap.as_ptr() as *mut Key1t;
        ptr.as_ref().unwrap()
    }
}

fn mmap_as_mut_key_10t(mmap: &MmapMut) -> &mut Key10t {
    unsafe {
        let ptr = mmap.as_ptr() as *mut Key10t;
        ptr.as_mut().unwrap()
    }
}

fn mmap_as_ref_key_10t(mmap: &Mmap) -> &Key10t {
    unsafe {
        let ptr = mmap.as_ptr() as *mut Key10t;
        ptr.as_ref().unwrap()
    }
}

fn endianness_check() {
    let b: [u8; 4] = [ 0x12, 0x34, 0x56, 0x78 ];
    let v: u32;
    unsafe {
        let p = (&b as *const u8) as *const u32;
        v = *p;
    }
    if v != 0x78563412 {
        println!("Currently only running on little-endian CPUs.");
        print!("This tool's usage of mmap for large keys would require ");
        println!("some additional code for properly supporting big-endian CPUS.");
        print!("Such code is rather simple, but without a way to test it, ");
        println!("we decided not to provide it.");
        println!("The lib itself should be fine.");
        std::process::exit(1);
    }
}

fn main() {
    endianness_check();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage_and_exit();
    }

    let mut rng = RandomSource{};
    let use_file = match std::env::var("ALWAYS_MMAP") {
        Ok(_v) => false,
        Err(_e) => true
    };

    match args[1].as_str() {

        "generate_key_16k" => {
            if args.len() != 3 {
                println!("Usage: yadacha generate_key_16k out_key_file");
                std::process::exit(1);
            }
            let mut key = alloc_key_16k();
            yadacha16k::init_key_16k(&mut rng, &mut key);
            let mut key_file = std::fs::OpenOptions::new()
                                .write(true).create_new(true).open(&args[2]).unwrap();
            write_key_16k(&key, &mut key_file);
            std::process::exit(0);
        },

        "generate_key_8m" => {
            if args.len() != 3 {
                println!("Usage: yadacha generate_key_8m out_key_file");
                std::process::exit(1);
            }
            let mut key = alloc_key_8m();
            yadacha8m::init_key_8m(&mut rng, &mut key);
            let mut key_file = std::fs::OpenOptions::new()
                                .write(true).create_new(true).open(&args[2]).unwrap();
            write_key_8m(&key, &mut key_file);
            std::process::exit(0);
        },

        "generate_key_1t" => {
            if args.len() != 3 {
                println!("Usage: yadacha generate_key_1t out_key_file");
                std::process::exit(1);
            }
            let key_file = std::fs::OpenOptions::new()
                            .read(true).write(true).create_new(true).open(&args[2]).unwrap();
            key_file.set_len(yadacha1t::KEY_SIZE as u64).unwrap();
            {
                let mmap = unsafe { MmapMut::map_mut(&key_file).expect("failed to memory map the key file") };
                let key = mmap_as_mut_key_1t(&mmap);
                let mut temp_set = alloc_temp_1t_set();
                let mut temp_seen = alloc_temp_1t_seen();
                yadacha1t::init_key_1t(&mut rng, key, &mut temp_set, &mut temp_seen);
                mmap.flush().unwrap();
            }
            std::process::exit(0);
        },

        "generate_key_10t" => {
            if args.len() != 3 {
                println!("Usage: yadacha generate_key_10t out_key_file");
                std::process::exit(1);
            }
            let key_file = std::fs::OpenOptions::new()
                            .read(true).write(true).create_new(true).open(&args[2]).unwrap();
            key_file.set_len(yadacha10t::KEY_SIZE as u64).unwrap();
            {
                let mmap = unsafe { MmapMut::map_mut(&key_file).expect("failed to memory map the key file") };
                let key = mmap_as_mut_key_10t(&mmap);
                let mut temp_set = alloc_temp_1t_set();
                let mut temp_seen = alloc_temp_1t_seen();
                yadacha10t::init_key_10t(&mut rng, key, &mut temp_set, &mut temp_seen);
                mmap.flush().unwrap();
            }
            std::process::exit(0);
        },

        "validate_key" => {
            if args.len() != 3 {
                println!("Usage: yadacha validate_key in_key_file");
                std::process::exit(1);
            }

            let mut key_file = File::open(&args[2]).unwrap();
            let key_size = key_file.metadata().unwrap().len();
            println!("validating key \"{}\" size {}",
                &args[2], key_size);

            match key_size as usize {
                yadacha16k::KEY_SIZE => {
                    let key = load_key_16k(&mut key_file);
                    let valid = yadacha16k::validate_key_16k(&key);
                    if valid {
                        println!("valid 16k key");
                        std::process::exit(0);
                    } else {
                        println!("invalid 16k key");
                        std::process::exit(1);
                    }
                },
                yadacha8m::KEY_SIZE => {
                    let key = load_key_8m(&mut key_file);
                    let valid = yadacha8m::validate_key_8m(&key);
                    if valid {
                        println!("valid 8m key");
                        std::process::exit(0);
                    } else {
                        println!("invalid 8m key");
                        std::process::exit(1);
                    }
                },
                yadacha1t::KEY_SIZE => {
                    let mmap = unsafe { Mmap::map(&key_file).expect("failed to memory map the key file") };
                    let key = mmap_as_ref_key_1t(&mmap);
                    let mut temp_seen = alloc_temp_1t_seen();
                    let valid = yadacha1t::validate_key_1t(key, &mut temp_seen);
                    if valid {
                        println!("valid 1t key");
                        std::process::exit(0);
                    } else {
                        println!("invalid 1t key");
                        std::process::exit(1);
                    }
                },
                yadacha10t::KEY_SIZE => {
                    let mmap = unsafe { Mmap::map(&key_file).expect("failed to memory map the key file") };
                    let key = mmap_as_ref_key_10t(&mmap);
                    let mut temp_seen = alloc_temp_1t_seen();
                    let valid = yadacha10t::validate_key_10t(key, &mut temp_seen);
                    if valid {
                        println!("valid 10t key");
                        std::process::exit(0);
                    } else {
                        println!("invalid 10t key");
                        std::process::exit(1);
                    }
                },
                _ => {
                    println!("bad key size");
                    std::process::exit(1);
                }
            }            
        },

        "encrypt" => {
            if args.len() != 5 {
                println!("Usage: yadacha encrypt key_file in_file out_file");
                std::process::exit(1);
            }
            let mut key_file = File::open(&args[2]).unwrap();
            let key_size = key_file.metadata().unwrap().len();
            println!("encrypting \"{}\" to \"{}\" using key \"{}\" size {}",
                &args[3], &args[4], &args[2], key_size);

            let mut in_file = File::open(&args[3]).unwrap();
            let in_file_size = in_file.metadata().unwrap().len();

            let mut preload: [u8; 16*1024] = [0; 16*1024];
            let preload_size = safe_read(&mut in_file, &mut preload);

            match in_file.rewind() {
                Ok(()) => {},
                Err(e) => {
                    println!("in_file rewind failed with {}", e);
                    std::process::exit(1);
                }
            }

            let mut out_file = std::fs::OpenOptions::new()
                                .write(true).create_new(true).open(&args[4]).unwrap();
            let mut chunk = [0; 65536];

            let yada: &mut dyn Yadacha;
            let mut yada_16k;
            let key_16k;
            let mut yada_8m;
            let key_8m;
            let mmap;
            let mut int_file;
            let mut yada_1t;
            let key_1t;
            let mut yada_10t;
            let key_10t;
            let nonces_size: usize;
            let tag_size: usize;

            match key_size as usize {
                yadacha16k::KEY_SIZE => {
                    key_16k = load_key_16k(&mut key_file);

                    if !yadacha16k::validate_key_16k(&key_16k) {
                        println!("invalid 16k key");
                        std::process::exit(1);
                    }
                    let nonce : Nonce16k = yadacha16k::new_nonce_16k(&mut rng);
                    for i in 0..nonce.len() {
                        safe_write(&mut out_file, &nonce[i].to_le_bytes());
                    }
                    let msg_nonce : MsgNonce16k = yadacha16k::new_msg_nonce_16k(&mut rng, &preload[..preload_size]);
                    for i in 0..msg_nonce.len() {
                        safe_write(&mut out_file, &msg_nonce[i].to_le_bytes());
                    }
                    yada_16k = yadacha16k::new_yadacha16k(&key_16k, &nonce, &msg_nonce);
                    yada = &mut yada_16k;
                    nonces_size = 40;
                    tag_size = 64;
                },
                yadacha8m::KEY_SIZE => {
                    key_8m = load_key_8m(&mut key_file);

                    if !yadacha8m::validate_key_8m(&key_8m) {
                        println!("invalid 8m key");
                        std::process::exit(1);
                    }
                    let nonce : Nonce8m = yadacha8m::new_nonce_8m(&mut rng);
                    for i in 0..nonce.len() {
                        safe_write(&mut out_file, &nonce[i].to_le_bytes());
                    }
                    let msg_nonce : MsgNonce8m = yadacha8m::new_msg_nonce_8m(&mut rng, &preload[..preload_size]);
                    for i in 0..msg_nonce.len() {
                        safe_write(&mut out_file, &msg_nonce[i].to_le_bytes());
                    }
                    yada_8m = yadacha8m::new_yadacha8m(&key_8m, &nonce, &msg_nonce);
                    yada = &mut yada_8m;
                    nonces_size = 80;
                    tag_size = 128;
                },
                yadacha1t::KEY_SIZE => {
                    mmap = unsafe { Mmap::map(&key_file).expect("failed to memory map the key file") };
                    key_1t = mmap_as_ref_key_1t(&mmap);

                    //if !yadacha1t::validate_key_1t(&key_1t) {
                    //    println!("invalid 1t key");
                    //    std::process::exit(1);
                    //}
                    let nonce : Nonce1t = yadacha1t::new_nonce_1t(&mut rng);
                    for i in 0..nonce.len() {
                        safe_write(&mut out_file, &nonce[i].to_le_bytes());
                    }
                    let msg_nonce : MsgNonce1t = yadacha1t::new_msg_nonce_1t(&mut rng, &preload[..preload_size]);
                    for i in 0..msg_nonce.len() {
                        safe_write(&mut out_file, &msg_nonce[i].to_le_bytes());
                    }
                    int_file = IntFile{ f: &mut key_file };
                    yada_1t = yadacha1t::new_yadacha1t(key_1t, &mut int_file, use_file, &nonce, &msg_nonce);
                    yada = &mut yada_1t;
                    nonces_size = 160;
                    tag_size = 256;
                },
                yadacha10t::KEY_SIZE => {
                    mmap = unsafe { Mmap::map(&key_file).expect("failed to memory map the key file") };
                    key_10t = mmap_as_ref_key_10t(&mmap);

                    //if !yadacha10t::validate_key_10t(&key_10t) {
                    //    println!("invalid 10t key");
                    //    std::process::exit(1);
                    //}
                    let nonce : Nonce1t = yadacha1t::new_nonce_1t(&mut rng);
                    for i in 0..nonce.len() {
                        safe_write(&mut out_file, &nonce[i].to_le_bytes());
                    }
                    let msg_nonce : MsgNonce1t = yadacha1t::new_msg_nonce_1t(&mut rng, &preload[..preload_size]);
                    for i in 0..msg_nonce.len() {
                        safe_write(&mut out_file, &msg_nonce[i].to_le_bytes());
                    }
                    int_file = IntFile{ f: &mut key_file };
                    yada_10t = yadacha10t::new_yadacha10t(key_10t, &mut int_file, use_file, &nonce, &msg_nonce);
                    yada = &mut yada_10t;
                    nonces_size = 160;
                    tag_size = 256;
                },
                _ => {
                    println!("bad key size");
                    std::process::exit(1);
                }
            }

            let associated_data = in_file_size.to_le_bytes();
            yada.init_encode(&associated_data);

            loop {
                let n = safe_read(&mut in_file, &mut chunk);
                if n == 0 { break; }
                yada.encode(&mut chunk[..n]);
                safe_write(&mut out_file, &chunk[..n]);
            }

            let tag = yada.finalize();
            safe_write(&mut out_file, &tag);

            let out_file_size = out_file.metadata().unwrap().len();
            //println!("in_file_size {} out_file_size {}", in_file_size, out_file_size);

            let extra_size = (nonces_size + tag_size) as u64;
            assert!(out_file_size == in_file_size + extra_size);

            println!("encrypted {} bytes", in_file_size);
            std::process::exit(0);
        },

        "decrypt" => {
            if args.len() != 5 {
                println!("Usage: yadacha decrypt key_file in_file out_file");
                std::process::exit(1);
            }

            let mut key_file = File::open(&args[2]).unwrap();
            let key_size = key_file.metadata().unwrap().len();
            println!("decrypting \"{}\" to \"{}\" using key \"{}\" size {}",
                &args[3], &args[4], &args[2], key_size);

            let mut in_file = File::open(&args[3]).unwrap();
            let in_file_size = in_file.metadata().unwrap().len();

            let mut out_file = std::fs::OpenOptions::new()
                                .write(true).create_new(true).open(&args[4]).unwrap();
            let mut chunk = [0; 65536];

            let yada: &mut dyn Yadacha;
            let mut yada_16k;
            let key_16k;
            let mut yada_8m;
            let key_8m;
            let mmap;
            let mut int_file;
            let mut yada_1t;
            let key_1t;
            let mut yada_10t;
            let key_10t;
            let nonces_size: usize;
            let tag_size: usize;

            match key_size as usize {
                yadacha16k::KEY_SIZE => {
                    key_16k = load_key_16k(&mut key_file);

                    if !yadacha16k::validate_key_16k(&key_16k) {
                        println!("invalid 16k key");
                        std::process::exit(1);
                    }
                    let mut nonce : Nonce16k = [0; 8];
                    for i in 0..nonce.len() {
                        nonce[i] = safe_read_u32(&mut in_file);
                    }
                    let mut msg_nonce : MsgNonce16k = [0; 2];
                    for i in 0..msg_nonce.len() {
                        msg_nonce[i] = safe_read_u32(&mut in_file);
                    }
                    yada_16k = yadacha16k::new_yadacha16k(&key_16k, &nonce, &msg_nonce);
                    yada = &mut yada_16k;
                    nonces_size = 40;
                    tag_size = 64;
                },
                yadacha8m::KEY_SIZE => {
                    key_8m = load_key_8m(&mut key_file);

                    if !yadacha8m::validate_key_8m(&key_8m) {
                        println!("invalid 8m key");
                        std::process::exit(1);
                    }
                    let mut nonce : Nonce8m = [0; 8];
                    for i in 0..nonce.len() {
                        nonce[i] = safe_read_u64(&mut in_file);
                    }
                    let mut msg_nonce : MsgNonce8m = [0; 2];
                    for i in 0..msg_nonce.len() {
                        msg_nonce[i] = safe_read_u64(&mut in_file);
                    }
                    yada_8m = yadacha8m::new_yadacha8m(&key_8m, &nonce, &msg_nonce);
                    yada = &mut yada_8m;
                    nonces_size = 80;
                    tag_size = 128;
                },
                yadacha1t::KEY_SIZE => {
                    mmap = unsafe { Mmap::map(&key_file).expect("failed to memory map the key file") };
                    key_1t = mmap_as_ref_key_1t(&mmap);

                    //if !yadacha1t::validate_key_1t(&key_1t) {
                    //    println!("invalid 1t key");
                    //    std::process::exit(1);
                    //}
                    let mut nonce : Nonce1t = [0; 8];
                    for i in 0..nonce.len() {
                        nonce[i] = safe_read_u128(&mut in_file);
                    }
                    let mut msg_nonce : MsgNonce1t = [0; 2];
                    for i in 0..msg_nonce.len() {
                        msg_nonce[i] = safe_read_u128(&mut in_file);
                    }
                    int_file = IntFile{ f: &mut key_file };
                    yada_1t = yadacha1t::new_yadacha1t(key_1t, &mut int_file, use_file, &nonce, &msg_nonce);
                    yada = &mut yada_1t;
                    nonces_size = 160;
                    tag_size = 256;
                },
                yadacha10t::KEY_SIZE => {
                    mmap = unsafe { Mmap::map(&key_file).expect("failed to memory map the key file") };
                    key_10t = mmap_as_ref_key_10t(&mmap);

                    //if !yadacha10t::validate_key_10t(&key_10t) {
                    //    println!("invalid 10t key");
                    //    std::process::exit(1);
                    //}
                    let mut nonce : Nonce1t = [0; 8];
                    for i in 0..nonce.len() {
                        nonce[i] = safe_read_u128(&mut in_file);
                    }
                    let mut msg_nonce : MsgNonce1t = [0; 2];
                    for i in 0..msg_nonce.len() {
                        msg_nonce[i] = safe_read_u128(&mut in_file);
                    }
                    int_file = IntFile{ f: &mut key_file };
                    yada_10t = yadacha10t::new_yadacha10t(key_10t, &mut int_file, use_file, &nonce, &msg_nonce);
                    yada = &mut yada_10t;
                    nonces_size = 160;
                    tag_size = 256;
                },
                _ => {
                    println!("bad key size");
                    std::process::exit(1);
                }
            }

            let extra_size = (nonces_size + tag_size) as u64;
            assert!(in_file_size >= extra_size);
            let ori_in_file_size = in_file_size - extra_size;
            let associated_data = ori_in_file_size.to_le_bytes();
            yada.init_decode(&associated_data);

            let mut to_write = ori_in_file_size as usize;
            loop {
                let mut todo = to_write;
                if todo > chunk.len() { todo = chunk.len(); }
                let n = safe_read(&mut in_file, &mut chunk[..todo]);
                if n == 0 { break; }
                yada.decode(&mut chunk[..n]);
                safe_write(&mut out_file, &chunk[..n]);
                to_write -= n;
            }

            assert!(tag_size <= 256);
            let mut tag = [0u8;256];
            let n = safe_read(&mut in_file, &mut tag[..tag_size]);
            if n != tag_size || !yada.validate(&tag[..tag_size]) {
                println!("validation failed");
                std::process::exit(1);
            }

            let out_file_size = out_file.metadata().unwrap().len();
            //println!("in_file_size {} out_file_size {}", in_file_size, out_file_size);
            assert!(out_file_size == ori_in_file_size);

            println!("decrypted {} bytes", ori_in_file_size);
            println!("validation succeeded");
            std::process::exit(0);
        },

        _ => {
            println!("Bad command: {}", args[1]);
            std::process::exit(1);
        }
    }
}
