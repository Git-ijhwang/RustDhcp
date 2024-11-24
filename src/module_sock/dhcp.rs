use core::str;
use std::{mem, option};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use crate::module_sock::module_sock::Clients;
use super::super::dump::dump::print_hex;
use super::super::ConfigMap;
use std::mem::size_of;
use byteorder::{ByteOrder, BigEndian};
use serde::{Deserialize, Serialize};

const HEADER_SIZE: i32 = 240;

enum DHCP_OPERATION_CODE {
    DHCP_START_REQUEST = 1,
    DHCP_REPLY,
}

/* htype & hlen */
enum DHCP_HTYPE {
    ETH_10MB = 1,
    ETH_10MB_LEN = 6,
}


enum DHCP_MESSAGE_TYPE {
    DHCPDISCOVER =   1,
    DHCPOFFER,
    DHCPREQUEST,
    DHCPDECLINE,
    DHCPACK,
    DHCPNAK,
    DHCPRELEASE,
    DHCPINFORM,
}

#[derive(Debug)]
pub struct DhcpHeader {
    op: u8,         //Operation Code; 1:BOOTREQUEST, 2:BOOTREPLY
    htype: u8,      //Hardware Address Type 1:10mb ethernet
    hlen: u8,       //Hardware address length
    hops: u8,       //Client set to zero

    xid: [u8; 4],       //Transaction ID. Filled by Client
    secs: u16,      //Seconds elapsed since client began address. Filled by Client
    flags: u16,     //Flag

    ciaddr: Ipv4Addr,    //Client IP Address
    yiaddr: Ipv4Addr,    //Your(Client) IP address
    siaddr: Ipv4Addr,    //Server IP Address
    giaddr: Ipv4Addr,    //Relay agent IP Address
    chaddr: [u8; 16], //Client Mac Address

    sname: [u8; 64], // Server host name, 64 bytes split into 32-byte chunks
    file: [u8; 128], // Boot file name, 128 bytes split into 32-byte chunks
    magic_cookie: [u8; 4],       //Magic Cookie
}

impl DhcpHeader {

    pub fn new( ) -> Self {
        DhcpHeader {
            op: 0,
            htype: 0,
            hlen: 0,
            hops: 0,
            xid: [0u8; 4],
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::new(0,0,0,0),
            yiaddr: Ipv4Addr::new(0,0,0,0),
            siaddr: Ipv4Addr::new(0,0,0,0),
            giaddr: Ipv4Addr::new(0,0,0,0),
            chaddr: [0u8; 16],
            sname: [0u8; 64],
            file: [0u8; 128],
            magic_cookie: [0u8; 4],
        }
    }

    // fn print_self (&self) {
    //     println!("{:#?}", self);
    // }
}

fn parse_option_field (client: &mut Arc<Mutex<Clients>>, buffer:&[u8], len: usize) {
    let mut msg_type = 0;
    let mut pos  = 0;
    let mut t = 0;
    let mut l = 0;
    let length = len - 4;

    loop {
        t = buffer[pos];
        pos += 1;

        if t == 255 {
            // println!("End of Option");
            break;
        }

        l = buffer[pos] as usize;
        pos += 1;

        let mut client_lock = client.lock().unwrap();
        match t {
            12 => {
                // println!("Host Name");
                match str::from_utf8(&buffer[pos..pos+l]) {
                    Ok(string) => client_lock.hostname = string.to_string(),
                    Err(e) => break,
                }

            },
            50 => {
                // println!("Request IP Address");
                client_lock.reqip = Ipv4Addr::new(buffer[pos], buffer[pos+1], buffer[pos+2], buffer[pos+3])
            },
            51 => {
                // println!("IP Address Lease Time");
                client_lock.lease_time = u16::from_be_bytes([buffer[pos],buffer[pos+1]]);
            },
            53 => {
                // println!("DHCP Message Type (Request)");
                msg_type = buffer[pos];
            },
            55 => {
                client_lock.req_list.fill(0);
                // println!("Parameter Request List Len: {}", l);
                for &v in &buffer[pos..pos+l] {
                    client_lock.req_list.push(v);
                }
            },
            57 => {
                // println!("Maximum DHCP Message Size ");
                client_lock.max_req_sz = u16::from_be_bytes([buffer[pos],buffer[pos+1]]);
            },
            61 => {
                // println!("Client Identifier");
                client_lock.cid.ctype = buffer[pos];
                client_lock.cid.cid[..l-1].copy_from_slice(&buffer[pos+1..pos+l]);
            },
            255 =>println!("Opeion End"),
            _ => println!("Unknown type {}", t)
        }

        pos += l;

        if pos >= length {
            break;
        }
    }
    // println!("{:#?}", client.lock().unwrap());
}



fn verify_header( client: &mut Arc<Mutex<Clients>>, buffer: &[u8], length: usize) -> i32 {
    println!("check the dhcp header size");

    if length < HEADER_SIZE as usize {
        println!("Received size is too small rcv:{}", length);
        return -1;
    }
    let mut header = DhcpHeader::new();
    from_buffer(buffer, &mut header);

    if header.op != DHCP_OPERATION_CODE::DHCP_START_REQUEST as u8 {
        println!("Operation Code: 0x{:02x}", header.op);
        return 1;
    }
    if header.htype != DHCP_HTYPE::ETH_10MB as u8 && header.htype != DHCP_HTYPE::ETH_10MB_LEN as u8 {
        println!("Hardware type: 0x{:02x}", header.htype);
        return 1;
    }

    client.lock().unwrap().tranxid = header.xid;
    client.lock().unwrap().magic_cookie = header.magic_cookie;
    client.lock().unwrap().elapsed_time = header.secs;
    client.lock().unwrap().cid.cid = header.chaddr;

    parse_option_field(client, &buffer[HEADER_SIZE as usize..], length-HEADER_SIZE as usize);
    HEADER_SIZE
}

    // fn slice_to_array(input: &[u8]) -> &[u8; 236] {
    //     let mut array = [0u8; 236];
    //     for (&x, p) in input.iter().zip(array.iter_mut()) {
    //     *p = x;
    //     }
    //     array
    // }
    // fn to_header(i: &[u8]) -> DhcpHeader {
    //     let arr = Self::slice_to_array(i);
    //     DhcpHeader::from()
    //     }
  
    /// Parse a DHCP header from a byte slice
    fn from_buffer(buffer: &[u8], header: &mut DhcpHeader) {
        let mut pos = 0;

        header.op = buffer[pos]; pos+=1;
        header.htype = buffer[pos]; pos+=1;
        header.hlen = buffer[pos]; pos+=1;
        header.hops = buffer[pos]; pos+=1;
        header.xid.copy_from_slice(&buffer[pos..pos+4]); pos+=4;
        header.secs = u16::from_be_bytes([buffer[pos], buffer[pos+1]]); pos+=2;
        header.flags = u16::from_be_bytes([buffer[pos], buffer[pos+1]]); pos+=2;
        // header.flags = buffer[pos] as u16; pos+=2;
        //     flags: BigEndian::read_u16(&buffer[10..12]),
        header.ciaddr = Ipv4Addr::new( buffer[pos], buffer[pos+1], buffer[pos+2], buffer[pos+3]); pos+=4;
        header.yiaddr = Ipv4Addr::new( buffer[pos], buffer[pos+1], buffer[pos+2], buffer[pos+3]); pos+=4;
        header.siaddr = Ipv4Addr::new( buffer[pos], buffer[pos+1], buffer[pos+2], buffer[pos+3]); pos+=4;
        header.giaddr = Ipv4Addr::new( buffer[pos], buffer[pos+1], buffer[pos+2], buffer[pos+3]); pos+=4;


        header.chaddr.copy_from_slice(&buffer[pos..pos+16]); pos+=16;
        header.sname.copy_from_slice(&buffer[pos..pos+64]); pos+=64;
        header.file.copy_from_slice(&buffer[pos..pos+128]); pos+=128;

        header.magic_cookie.copy_from_slice(&buffer[pos..pos+4]);
        //     sname: buffer[44..108].try_into().unwrap_or([0; 64]),
        //     file: buffer[108..236].try_into().unwrap_or([0; 128]),
    }

fn make_dhcp_response() {}
fn send_dhcp_msg(){}


/// DHCP OFFER 메시지 생성
fn create_dhcp_header(client: &mut Arc<Mutex<Clients>>, buffer: &[u8])
{
    let mut rsp = DhcpHeader::new();
    let mut options:Vec<u8> = Vec::new();

    //Msg Type: 2
    rsp.op = 0x02;
    //HW type: 0x01
    rsp.htype = 0x01;
    //addr len 6
    rsp.hlen = 0x06;
    //hops 0
    rsp.hops = 0x00;
    //tranxid: 2fe3016a
    rsp.xid = client.lock().unwrap().tranxid;
    //sec elapsed 42
    rsp.secs = client.lock().unwrap().elapsed_time;
    //bootp flag 0x00
    rsp.flags = 0;
    //client ip 00
    rsp.ciaddr = Ipv4Addr::new(0,0,0,0);
    //your ip 2.19
    //rsp.yiaddr = 
    //next svr ip : 0.0.0.0
    rsp.siaddr = Ipv4Addr::new(0,0,0,0);
    //relay agent: 0.0.0.0
    rsp.giaddr = Ipv4Addr::new(0,0,0,0);
    //mac: 3c 22 fb 7d 8b, ee
    rsp.chaddr = client.lock().unwrap().hw_addr;
    //client hw addr padding 00
    // host name -
    //rsp.sname = 0;
    //boot file -
    //magic - 63 82 53 63
    rsp.magic_cookie = client.lock().unwrap().magic_cookie;
    for t in &client.lock().unwrap().req_list {
        let mut l = 0;
        match *t {
            //option 53 DHCP Msg Type :2
            53 => {
                //Type
                options.push(*t); l+=1;
                //Length
                options.push(1); l+=1;
                //Value
                options.push(2); l+=1;
            }
            //option 54 svr identifier 192.168.2.1
            54 => {
                //Type
                options.push(*t); l+=1;
                //Length
                options.push(4); l+=1;
        ConfigMap::get_value("Addr".to_string());
        ConfiGmap::read_conf
        ConfigMap::get_value(&self, target)
            }

            //option 51 ip lease time: 259200(3day)
            51 => {}
            //option 1 subnet mask 255.25.255.0
            1 => {}
            //option 3 router 192.168.2.1
            3 => {}
            //option 6 DNS len 8 192.168.2.1  142.166.166.166
            6 => {}
            //option 15 Domain name home
            15 => {}
            //option 0xff 16bytes
            _ => {}
        }
    }

    if !client.lock().unwrap().ip.is_private() {
        /* Allocation IP Address */
        rsp.yiaddr = Ipv4Addr::new(192,168,10,10);
    }
    // TODO: rsp.chaddr = client.lock().unwrap().
}


pub fn dhcp_handle( client: &mut Arc<Mutex<Clients>>, buffer: &[u8], length: usize) {
    // let mut header;

    let ret = verify_header(client, buffer, length);
    if ret < 0 {
        println!("verify occured");
        return
    }

    // 2. 응답 생성
    let mut rsp = create_dhcp_header(client, &buffer);

    // let client_lock = client.lock().unwrap();
    // let dst_bind = format!("{}:{}",client_lock.ip, client_lock.port as u32);
    // header = offer_header.unwrap();

}