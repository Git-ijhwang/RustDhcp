use crate::module_sock::dhcp::DhcpHeader;
use crate::module_sock::dhcp::dhcp_handle;
// use super::dump::print_hex;
use super::super::dump::dump::print_hex;

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::net::UdpSocket;
use std::thread;

#[derive(Debug)] 
pub struct ClientId {
    pub ctype: u8,
    pub cid: [u8; 16],
}
impl ClientId {
    fn new() -> Self {
        ClientId {
            ctype: 0,
            cid: [0u8; 16]
        }
    }
}

#[derive(Debug)] 
pub struct Clients {
    pub ip: Ipv4Addr,
    pub port: u8,
    pub socket: UdpSocket,
    pub tranxid: [u8;4],
    pub hostname: String,
    pub reqip: Ipv4Addr,
    pub allocate_ip: Ipv4Addr,
    pub lease_time: u16,
    pub elapsed_time: u16,
    pub req_list: Vec<u8>,
    pub max_req_sz: u16,
    pub cid: ClientId,
    pub hw_addr: [u8; 16],
    pub magic_cookie: [u8; 4],
    pub msg_type: u8,
}

pub type SharedClient = Arc< Mutex< Clients >>;


impl Clients {
    pub fn new(ip: Ipv4Addr, port: u8, socket: &UdpSocket) -> SharedClient {
        Arc::new( Mutex::new(Clients{
            ip,
            port,
            socket : socket.try_clone().expect("error"),
            tranxid: [0u8;4],
            hostname: String::new(),
            reqip: Ipv4Addr::new(0,0,0,0),
            allocate_ip: Ipv4Addr::new(0,0,0,0),
            lease_time: 0,
            elapsed_time: 0,
            req_list: Vec::new(),
            max_req_sz: 0,
            cid: ClientId::new(),
            hw_addr: [0u8; 16],
            magic_cookie: [0u8; 4],
            msg_type: 0,
        }))
    }

    pub fn print_self (&self) {
        println!("{:#?}", self);
    }
}


fn dup_check (list:& mut Vec<SharedClient>, src_ip:Ipv4Addr ) -> bool {
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
        let mut ip_addr = Ipv4Addr::new(0,0,0,0);
        println!("Waiting...");

        match socket.recv_from(&mut buffer) {
            Ok((size, src)) => {

                println!("Received Size: {}", size);
                if let IpAddr::V4(ip) = src.ip() {
                    ip_addr = ip;
                }
                else {
                    println!("Not support IP address");
                }
                let port = src.port() as u8;

                /* IP duplication check */
                if !dup_check(&mut client_list, ip_addr.clone()) {
                    /* new */
                    println!("New one.  IP address: {}, Port: {}", ip_addr, port);

                    client = Some(Clients::new(ip_addr, port, &socket));
                    client_list.push(client.clone().unwrap());
                } else {
                    println!("IP address: {}, Port: {}", ip_addr, port);
                }

                print_hex(&buffer[..], size);

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
