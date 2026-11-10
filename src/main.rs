use std::{env::args, io::{self, Read, Write}, iter::Skip, net::{TcpListener, TcpStream}};

use base64::prelude::*;
use ring::signature::Ed25519KeyPair;

fn sign_file(mut file: std::fs::File, keypair: Ed25519KeyPair) -> Vec<u8> {
    let mut file_bytes= vec![];
    file.read_to_end(&mut file_bytes).unwrap();
    let sign = keypair.sign(&file_bytes);
    Vec::from(sign.as_ref())   
}

fn keypair_from_pass(pass: &str) -> Ed25519KeyPair {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(pass.as_bytes());
    let digest = ctx.finish();
    let res =ring::signature::Ed25519KeyPair::from_seed_unchecked(digest.as_ref()).unwrap();
    res
}

fn client_upload(info: ClientInfoUpload, stream: TcpStream) {
    let path = filename::file_name(&info.file).unwrap();
    let name = format!("{}", path.file_name().unwrap().display());
    let keypair = keypair_from_pass(&info.password);
    let signtaure = BASE64_STANDARD.encode(&sign_file(info.file.try_clone().unwrap(), keypair));

    

}

fn main() {
    let connection = parse_arguments().unwrap();

    match connection.mode {
        Mode::Server => todo!(),
        Mode::Client(i) => client_upload(i, connection.stream),
    }

    println!("Hello, world!");
}

struct ConnectionType {
    stream: TcpStream,
    mode: Mode
}

struct ClientInfoUpload {
    password: String,
    file: std::fs::File,
}

enum Mode {
    Server,
    Client(ClientInfoUpload)
}

fn parse_client_arguments() -> Option<ClientInfoUpload> {
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
            "-f" => file = Some(std::fs::File::open(args.next()?).unwrap()),
            _ => continue,
        };
    }

    match (pass, file) {
        (Some(p), Some(f)) => Some(ClientInfoUpload {password: p, file: f}),
        _ => None
    }
}

// Parses input arguments.
fn parse_arguments() -> Option<ConnectionType> { // std::env::args()

    let mut args = std::env::args();
    args.next();
    let first_arg = dbg!(args.next()?);

    let (mode, stream) = match first_arg.as_str() {
        "-a" => (Mode::Client(parse_client_arguments()?), parse_address(&args.next()?)),
        "-S" => (Mode::Server, wait_for_connection()),
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

fn wait_for_connection() -> TcpStream {
    let conn = TcpListener::bind("0.0.0.0:6767").unwrap().incoming().next().unwrap();
    conn.unwrap()
}