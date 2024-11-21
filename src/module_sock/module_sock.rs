use crate::module_sock::dhcp::dhcp_handle;
// use super::dump::print_hex;
use super::super::dump::dump::print_hex;

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::net::UdpSocket;
use std::thread;

#[derive(Debug)] 
pub struct Clients {
    pub ip: String,
    pub port: u8,
    pub tranxid: [u8;4],
    pub hostname: String,
    pub reqip: Ipv4Addr,
    pub lease_time: u32,
    pub req_list: [u8; 16],
    pub cid: [u8; 16],
}

pub type SharedClient = Arc< Mutex< Clients >>;

impl Clients {
    pub fn new(ip: String, port: u8) -> SharedClient {
        Arc::new( Mutex::new(Clients{
            ip,
            port,
            tranxid: [0u8;4],
            hostname: String::new(),
            reqip: Ipv4Addr::new(0,0,0,0),
            lease_time: 0,
            req_list: [0u8; 16],
            cid: [0u8; 16]
        }))
    }

    fn print_list (&self) {
        println!("{}, {}", self.ip, self.port);
    }
}


fn dup_check (list:& mut Vec<SharedClient>, src_ip:String ) -> bool {
    for item in list {
        if item.lock().unwrap().ip == src_ip {
            return true;
        }
    }
    return false;
}

// fn recv_func(tx: Sender<String>, socket: UdpSocket){
pub fn recv_func(socket: UdpSocket){
    let mut buffer = [0u8; 1024];
    let mut client_list : Vec<SharedClient> = Vec::new();
    let mut client = None;

    loop {
        client = None;
        println!("Waiting...");

        match socket.recv_from(&mut buffer) {
            Ok((size, src)) => {

                let ip = src.ip().to_string();
                let port = src.port() as u8;

                /* IP duplication check */
                if !dup_check(&mut client_list, ip.clone()) {
                    /* new */
                    println!("New one.  IP address: {}, Port: {}", ip, port);

                    client = Some(Clients::new(ip, port));
                    client_list.push(client.clone().unwrap());
                } else {
                    println!("IP address: {}, Port: {}", ip, port);
                }

                print_hex(&buffer[..size], size);

                // let mut data = buffer[..size].to_vec();
                dhcp_handle(&mut client.clone().unwrap(), &buffer[..size], size);
                buffer = [0; 1024];
            }

            Err(e) => {
                eprintln!("Error receiving data: {:?}", e);
            }
        }

        // CPU 사용을 줄이기 위해 짧게 대기
        thread::sleep(Duration::from_millis(100));
    } //loop
}
