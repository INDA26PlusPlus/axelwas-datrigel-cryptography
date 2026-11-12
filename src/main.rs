use std::{collections::HashMap, env::args, fs::File, hash::Hash, io::{self, Read, Write}, iter::Skip, net::{TcpListener, TcpStream}, str::Bytes};

use base64::prelude::*;
use ring::{aead::{AES_256_GCM, Aad, BoundKey, NONCE_LEN, Nonce, NonceSequence, SealingKey, UnboundKey}, signature::UnparsedPublicKey, rand::{SecureRandom, SystemRandom}, signature::{ED25519, Ed25519KeyPair, KeyPair}};

use crate::nonce::OneTimeNonce;

mod nonce;

fn sign_file(mut file: std::fs::File, name: &str, keypair: Ed25519KeyPair) -> Vec<u8> {
    let mut file_bytes= vec![];
    file.read_to_end(&mut file_bytes).unwrap();
    file_bytes.extend(name.bytes());
    let sign = keypair.sign(&file_bytes);
    Vec::from(sign.as_ref())   
}

fn verify_sign(mut file: Vec<u8>, name: &str, sign: &[u8], keypair: Ed25519KeyPair) -> bool {
    let public_key = keypair.public_key();
    let peer_public_key = UnparsedPublicKey::new(&ED25519, public_key.as_ref());

    file.extend(name.as_bytes());

    println!("{:?}", &file);
    peer_public_key.verify(&file, &sign).is_ok()
}

fn keypair_from_pass(pass: &str) -> Ed25519KeyPair {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(pass.as_bytes());
    let digest = ctx.finish();
    let res = ring::signature::Ed25519KeyPair::from_seed_unchecked(digest.as_ref()).unwrap();
    res
}

fn hash_bytes(bytes: Vec<u8>) -> Vec<u8> {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(&bytes);
    let digest = ctx.finish();

    Vec::from(digest.as_ref())
}

fn aeskey_from_pass(pass: &str) -> UnboundKey {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(pass.as_bytes());
    let digest = ctx.finish();

    let unbound_key = UnboundKey::new(&AES_256_GCM, digest.as_ref()).unwrap();
    unbound_key
}

fn generate_nonce() -> (String, OneTimeNonce) {
    let rng = SystemRandom::new();
    let mut ret = [0; NONCE_LEN];

    rng.fill(&mut ret);

    

    (BASE64_STANDARD.encode(ret), nonce::OneTimeNonce::new(ret))
}

fn encrypt_file<T: NonceSequence>(filename: &str, key: UnboundKey, nonce: T) -> Vec<u8> {
    let mut f = std::fs::File::open(filename).unwrap();
    
    let mut sealing_key = ring::aead::SealingKey::new(key, nonce);
    
    let mut in_out = Vec::new();
    f.read_to_end(&mut in_out).unwrap();

    dbg!(&in_out);

    sealing_key.seal_in_place_append_tag(Aad::empty(), &mut in_out).unwrap();

    in_out
}

fn decrypt_file<T: NonceSequence>(mut bytes: Vec<u8>, key: UnboundKey, nonce: T) -> Vec<u8> {
    let mut opening_key = ring::aead::OpeningKey::new(key, nonce);

    opening_key.open_in_place(Aad::empty(), &mut bytes).unwrap();

    bytes
}

fn client_upload(info: ClientInfo, mut stream: TcpStream) {
    let file = std::fs::File::open(&info.file).unwrap();

    let path = filename::file_name(&file.try_clone().unwrap()).unwrap();
    let name = format!("{}", path.file_name().unwrap().display());
    let keypair = keypair_from_pass(&info.password);
    let signtaure = BASE64_STANDARD.encode(&sign_file(file.try_clone().unwrap(), &info.file, keypair));
    let nonce = generate_nonce();

    let bytes = encrypt_file(&info.file, aeskey_from_pass(&info.password), nonce.1); 
    
    let mut to_send: Vec<u8> = vec![];
    to_send.extend(format!("PUT {}\nsignature: {}\nnonce: {}\nlength: {}\n\n", name, signtaure, nonce.0, bytes.len()).as_bytes());
    to_send.extend(bytes);

    stream.write(&to_send).unwrap();
}

struct Message {
    headers: HashMap<String, String>,
    data: Vec<u8>
}

fn read_to_end_message(stream: &mut TcpStream) -> Message {
    
    let mut lines = vec![];
    let mut line = String::new();
    let mut buff = [0];
    loop {
        stream.read(&mut buff).unwrap();
        let c = char::from(buff[0]);
        if c != '\n' {
            line.push(c);
            continue;
        } else {
            if line == "" {
                break;
            }
            lines.push(line);
            line = String::new();
        }
    }

    let mut hashmap = HashMap::new();
    for line in lines {
        let mut split = line.split(": ");
        let key = split.next().unwrap();
        let value = split.next().unwrap();

        hashmap.insert(String::from(key), String::from(value));
    }

    let length = hashmap.get("length").map(|s| s.parse::<usize>());
    let length = length.unwrap().unwrap();

    let mut buff = Vec::new();
    for _ in 0..length { buff.push(0); }

    stream.read_exact(&mut buff).unwrap();

    Message {
        headers: hashmap,
        data: buff
    }
}

fn client_download_get_file(info: &ClientInfo, mut stream: TcpStream) -> Vec<u8> {
    stream.write(format!("GET {}\n\n", info.file).as_bytes()).unwrap();
    let msg = read_to_end_message(&mut stream);

    let nonce_vec = BASE64_STANDARD.decode(msg.headers.get("nonce").unwrap()).unwrap();
    let nonce = [nonce_vec[0], nonce_vec[1], nonce_vec[2], nonce_vec[3], nonce_vec[4], nonce_vec[5], nonce_vec[6], nonce_vec[7], nonce_vec[8], nonce_vec[9], nonce_vec[10], nonce_vec[11]];
    let signature = msg.headers.get("signature").unwrap();
    let signature = BASE64_STANDARD.decode(signature).unwrap();
    let keypair = keypair_from_pass(&info.password);
    let decrypted = decrypt_file(msg.data, aeskey_from_pass(&info.password), nonce::OneTimeNonce::new(nonce));
    let s = &decrypted[0..decrypted.len() - 16];

    println!("{:?}", s);
    
    let is_real = verify_sign(Vec::from(s), &info.file, &signature, keypair);

    if !is_real {
        println!("signature not valid");
        panic!("sign not valid");
    }

    return Vec::from(s);
}

fn client_download(info: ClientInfo, stream: TcpStream) {
    let mut to_write = client_download_get_file(&info, stream);

    let mut file = std::fs::File::create_new(&info.file).unwrap();
    file.write_all(&mut to_write).unwrap();
    file.flush().unwrap();
    drop(file);
}

fn read_list(stream: &mut TcpStream) -> Vec<String> {
    let mut b = [0];
    let mut s = String::new();

    loop {
        stream.read_exact(&mut b).unwrap();

        s.push(char::from(b[0]));

        if s.ends_with("\n\n") {
            break;
        }
    }

    let ret: Vec<&str> = s.split("\n").collect();

    ret.into_iter().filter(|p| *p != "").map(|s| String::from(s)).collect()
}

fn client_merkle_tree(info: ClientInfo, mut stream: TcpStream) {
    stream.write(b"LIST\n\n").unwrap();
    let mut files = read_list(&mut stream);
    files.sort();

    let mut hashes = vec![];
    for file in files {
        let res = client_download_get_file(&ClientInfo { password: info.password.clone(), file }, stream.try_clone().unwrap());
        hashes.extend(hash_bytes(res));

    }

    let final_hash = BASE64_STANDARD.encode(hash_bytes(hashes));

    let mut to_write = std::fs::File::create(info.file).unwrap();

    to_write.write(format!("merkleTreeHash: {}", final_hash).as_bytes()).unwrap();
    println!("merkleTreeHash: {}", final_hash);

}

fn main() {
    let mut connection = parse_arguments().unwrap();

    match connection.mode {
        Mode::Server(mut memory, listner) => {loop {connection_mode_server(&mut memory, connection.stream); (connection.stream, _) = listner.accept().unwrap()}},
        Mode::ClientUpload(i) => client_upload(i, connection.stream),
        Mode::ClientDownload(i) => client_download(i, connection.stream),
        Mode::ClientMerkleTree(i) => client_merkle_tree(i, connection.stream),
    }

    println!("Hello, world!");
}

struct ConnectionType {
    stream: TcpStream,
    mode: Mode
}

// The file on upload is the name of the LocalFile and 
struct ClientInfo {
    password: String,
    file: String,
}

enum Mode {
    Server(HashMap<String, Vec<u8>>, TcpListener),
    ClientUpload(ClientInfo),
    ClientDownload(ClientInfo),
    ClientMerkleTree(ClientInfo)
}

fn parse_client_arguments() -> Option<ClientInfo> {
    let mut args = std::env::args();    

    let mut pass = None;
    let mut file = None;
    loop {
        let arg = match args.next() {
            Some(s) => s,
            None => break,
        };
        match arg.as_str() {
            "-p" => pass = Some(args.next()?),
            "-f" => file = Some(args.next()?),
            _ => continue,
        };
    }

    match (pass, file) {
        (Some(p), Some(f)) => Some(ClientInfo {password: p, file: f}),
        _ => None
    }
}

// Parses input arguments.
fn parse_arguments() -> Option<ConnectionType> { // std::env::args()

    let mut args = std::env::args();
    args.next();
    let first_arg = dbg!(args.next()?);

    let (mode, stream) = match first_arg.as_str() {
        "-a" => (Mode::ClientUpload(parse_client_arguments()?), parse_address(&args.next()?)),
        "-d" => (Mode::ClientDownload(parse_client_arguments()?), parse_address(&args.next()?)),
        "-m" => (Mode::ClientMerkleTree(parse_client_arguments()?), parse_address(&args.next()?)),
        "-S" => { let (stream, listner) = wait_for_connection(); (Mode::Server(memory_init(), listner), stream)},
        _ => return None
    };

    return Some(ConnectionType {
        mode,
        stream
    });
}

// Establishes a tcp stream to server.
fn parse_address(address: &str) -> TcpStream {
    TcpStream::connect(address.trim()).expect("Could not connect")
}

fn wait_for_connection() -> (TcpStream, TcpListener) {
    let listner = TcpListener::bind("0.0.0.0:6767").unwrap();
    let conn = listner.incoming().next().unwrap();
    (conn.unwrap(), listner)
}

enum Command {
    GET,
    PUT,
    LIST,
}

//Creates a empty hashmap.
fn memory_init() -> HashMap<String, Vec<u8>> {
    let mut hashmap: HashMap<String, Vec<u8>> = HashMap::new();
    hashmap
}

// Server setup and execution
fn connection_mode_server(memory: &mut HashMap<String, Vec<u8>>, mut stream: TcpStream) {
    let (command, file_name) = server_read_firstline(&mut stream);

    let response = match command {
        Command::GET => fetch_file_contents(file_name, memory, &mut stream),
        Command::PUT => put_file_contents(file_name, memory, &mut stream),
        Command::LIST => list_all_files(memory, &mut stream),
    };
    
    stream.write(&response);
}

// Store a file in memory, with all headers -> returns a message as one block.
fn put_file_contents(file_name: String, memory: &mut HashMap<String, Vec<u8>>, stream: &mut TcpStream) -> Vec<u8> {
    let message = read_to_end_message(stream);

    let sig = message.headers.get("signature").unwrap();
    let length = message.headers.get("length").unwrap();
    let nonce = message.headers.get("nonce").unwrap();

    let mut headers = format!("signature: {sig}\nlength: {length}\nnonce: {nonce}\n\n").as_bytes().to_vec();
    headers.extend(message.data);

    memory.insert(file_name, headers);

    "OK".as_bytes().to_vec()
}

// Fetch file from memory
fn fetch_file_contents(file_name: String, memory: &mut HashMap<String, Vec<u8>>, stream: &mut TcpStream) -> Vec<u8> {
    let message = memory.get(&file_name).unwrap().clone();
    
    message
}

// Lists all files in server memory
fn list_all_files(memory: &mut HashMap<String, Vec<u8>>, stream: &mut TcpStream) -> Vec<u8> {
    let mut buff = String::new();
    
    for keys in memory.keys() {
        buff.push_str(&format!("{keys}\n"));
    }

    buff.as_bytes().to_vec()
}

// reads first line for parsing GET, PUT, LIST.
fn server_read_firstline(mut stream: &mut TcpStream) -> (Command, String) {
    let mut line = String::new();
    let mut buff = [0];

    let mut command_str: &str; 
    let mut file_name: String;

    loop {
        stream.read(&mut buff).unwrap();
        let c = char::from(buff[0]);
        if  c != '\n' {
            line.push(c);
            continue;
        } else {
            let mut split = line.split(' ');
            command_str = split.next().unwrap();
            file_name = split.next().unwrap().to_owned();

            break;
        }
    }

    let command = match command_str {
        "GET" => Command::GET,
        "PUT" => Command::PUT,
        "LIST" => Command::LIST,
        _ => panic!("Invalid recived invalid client command")
    };
    
    return (command, file_name)
}