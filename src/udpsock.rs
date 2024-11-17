mod dhcp;

use std::sync::{ Arc, Mutex};
use std::sync::mpsc::{Sender, Receiver};
use std::time::Duration;
use std::net::UdpSocket;
use std::io::{stdin, Bytes, Result, Read};
use std::thread;
use dhcp::dhcp_handle;

pub struct Clients {
    ip: String,
    port: u8,
    tranxid: u32,
}
pub type SharedClient = Arc< Mutex< Clients >>;

impl Clients {
    pub fn new(ip: String, port: u8, tranxid: u32) -> SharedClient {
        Arc::new( Mutex::new( Clients{ ip, port, tranxid }
            )

        )
    }

    fn print_list (&self) {
        println!("{}, {}", self.ip, self.port);
    }
}


// fn send_func(socket_clone: UdpSocket, dst_bind: String) {

//     loop {
//         let mut input_buffer = String::new();

//         let response = get_input(&mut input_buffer);
//             socket_clone.send_to(response, dst_bind.as_str()).expect("Failed to send response");

//         // CPU를 너무 많이 사용하지 않도록 짧게 대기합니다.
//         thread::sleep(Duration::from_millis(100));
//     } //loop
// }

fn dup_check (list:& mut Vec<SharedClient>, src_ip:String ) -> bool {
    for item in list {
        if item.lock().unwrap().ip == src_ip {
            return true;
        }
    }
    return false;
}


fn print_hex(buffer: &[u8], length: usize) {
    let length = length.min(buffer.len());

    for i in 0..length {
        print!("{:02X} ", buffer[i]);
        if (i + 1) % 8 == 0 {
            print!("  "); // 16바이트마다 줄 바꿈
        }
        if (i + 1) % 16 == 0 {
            println!(); // 16바이트마다 줄 바꿈
        }
    }
    println!(); // 마지막 줄 바꿈
}

// fn recv_func(tx: Sender<String>, socket: UdpSocket){
pub fn recv_func(socket: UdpSocket){
    let mut buffer = [0; 1024];
    let mut client_list : Vec<SharedClient> = Vec::new();

    loop {
        let mut client = None;
        println!("Waiting...");

        match socket.recv_from(&mut buffer) {
            Ok((size, src)) => {

                let ip = src.ip().to_string();
                let port = src.port() as u8;

                /* IP duplication check */
                if !dup_check(&mut client_list, ip.clone()) {
                    /* new */
                    client = Some(Clients::new(ip, port, 0));
                    client_list.push(client.clone().unwrap());
                }

                print_hex(&buffer[..size], size);

                // let mut data = buffer[..size].to_vec();
                dhcp_handle(&mut client.clone().unwrap(), &buffer[..size], size);
            }

            Err(e) => {
                eprintln!("Error receiving data: {:?}", e);
            }
        }

        // CPU 사용을 줄이기 위해 짧게 대기
        thread::sleep(Duration::from_millis(100));
    } //loop
}
