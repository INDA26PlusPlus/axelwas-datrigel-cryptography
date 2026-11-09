use std::{env::args, io::{self, Read, Write}, iter::Skip, net::{TcpListener, TcpStream}};

fn main() {
    println!("Hello, world!");
}

struct Connection_Type {
    stream: TcpStream,
    mode: Mode
}

enum Mode {
    server,
    client
}

// Parses input arguments.
fn parse_arguments(argument_list: Vec<&str>, connection_type: &mut Connection_Type) { // std::env::args()
    let mut buff: Option<&str> = None;

    for argument in argument_list { 
        match buff {
            Some("-a") => parse_address(argument, connection_type),
            Some("-S") => connection_type.mode = Mode::server,
            None => continue,
            _ => todo!() // Skip or do nothing, can also panic though need to fix that input args are not paniced on.
        };

        // Buffer the previous input.
        buff = Some(argument);
    };
}

// Establishes a tcp stream to server.
fn parse_address(address: &str, connection_type: &mut Connection_Type) {
    connection_type.stream = TcpStream::connect(address.trim()).expect("Could not connect");
}