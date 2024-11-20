use crate::module_sock::dhcp::dhcp_handle;
// use super::dump::print_hex;
use super::super::dump::dump::print_hex;

use std::sync::{ Arc, Mutex};
use std::time::Duration;
use std::net::UdpSocket;
use std::thread;

pub struct Clients {
    pub ip: String,
    pub port: u8,
    pub tranxid: u32,
}
pub type SharedClient = Arc< Mutex< Clients >>;

impl Clients {
    pub fn new(ip: String, port: u8, tranxid: u32) -> SharedClient {
        Arc::new( Mutex::new( Clients{ ip, port, tranxid }))
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

                    client = Some(Clients::new(ip, port, 0));
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
