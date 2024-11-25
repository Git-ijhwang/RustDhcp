use core::str;
use std::str::FromStr;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, MutexGuard};
use crate::module_sock::module_sock::Clients;
use super::super::dump::dump::print_hex;
use super::super::ConfigMap;
use std::mem::size_of;
use crate::{config, get_ip, CONFIG_MAP};
use std::ptr;
use super::super::main;

const HEADER_SIZE: i32 = 240;

const DHCP_START_REQUEST: u8 = 0x01;
const DHCP_REPLY: u8 = 0x02;

/* htype & hlen */
const ETH_10MB: u8 = 0x01;
const ETH_10MB_LEN: u8 = 0x06;

const DHCPDISCOVER: u8 = 0x01;
const DHCPOFFER: u8 = 0x02;
const DHCPREQUEST: u8 = 0x03;
const DHCPDECLINE: u8 = 0x04;
const DHCPACK: u8 = 0x05;
const DHCPNAK: u8 = 0x06;
const DHCPRELEASE: u8 = 0x07;
const DHCPINFORM: u8 = 0x08;


#[repr(C)]
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
                client_lock.msg_type = buffer[pos];
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

    if header.op != DHCP_START_REQUEST as u8 {
        println!("Operation Code: 0x{:02x}", header.op);
        return -1;
    }
    if header.htype != ETH_10MB as u8 && header.htype != ETH_10MB_LEN as u8 {
        println!("Hardware type: 0x{:02x}", header.htype);
        return -1;
    }

    client.lock().unwrap().tranxid = header.xid;
    client.lock().unwrap().magic_cookie = header.magic_cookie;
    client.lock().unwrap().elapsed_time = header.secs;
    client.lock().unwrap().cid.cid = header.chaddr;
    client.lock().unwrap().hw_addr = header.chaddr;

    parse_option_field(client, &buffer[HEADER_SIZE as usize..], length-HEADER_SIZE as usize);
    println!("Option field parsing.... Done. ");
    return header.op as i32;

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
fn create_dhcp_header( client: &mut Arc<Mutex<Clients>>, buffer: &mut [u8], msg_type: u8) -> usize {
    let config = CONFIG_MAP.read().unwrap();
    let client_lock = client.lock().unwrap();
    let mut rsp = DhcpHeader::new();

    println!("Start DHCP Header creating");
    rsp.op = msg_type; //Msg Type
    rsp.htype = ETH_10MB; //HW type
    rsp.hlen = 0x06; //addr len
    rsp.hops = 0x00; //hops
    rsp.xid.clone_from_slice(&client_lock.tranxid); //tranxid
    rsp.secs = client_lock.elapsed_time; //sec elapsed time
    rsp.flags = 0; //bootp flag 
    rsp.ciaddr = Ipv4Addr::new(0,0,0,0); //client ip
    rsp.yiaddr = client_lock.allocate_ip;
    let str = config.get("Addr").unwrap();
    rsp.siaddr = Ipv4Addr::from_str(&str).unwrap();
    rsp.giaddr = Ipv4Addr::new(0,0,0,0); //relay agent
    rsp.chaddr = client_lock.hw_addr; //mac
    rsp.magic_cookie = client_lock.magic_cookie; //magic

    // Convert to buffer
    unsafe {
        let struct_ptr = &rsp as *const DhcpHeader as *const u8;
        ptr::copy_nonoverlapping(struct_ptr, buffer.as_mut_ptr(), HEADER_SIZE as usize);
    }

    return HEADER_SIZE as usize;
}


fn create_dhcp_option( client: &mut Arc<Mutex<Clients>>, buffer: &mut [u8], option_type:u8) -> usize {
    let config = CONFIG_MAP.read().unwrap();
    let mut options: [u8;128] = [0u8;128];
    let mut l = 0;
    // print_hex(buffer, HEADER_SIZE as usize);
    println!("Start DHCP Option creating");

    let client_lock = client.lock().unwrap();
    {
        //Type
        options[l] = 53; l+=1;
        //Length
        options[l] = 1; l+=1;
        //Value
        options[l] = option_type; l+=1;
    }

    {
        //Type
        options[l] = 54; l+=1;
        //Length
        options[l] = 4; l+=1;
        //Value
        let ip = config.get("Addr");
        if ip.is_none() {
            println!("Key(Addr) not found");
        }
        let addr = Ipv4Addr::from_str(&(ip.unwrap()));
        match addr {
            Ok(ip) => {
                options[l..l+4].copy_from_slice(&(ip.octets()));
            }
            Err(e) => {
                println!("Failed to parse IP address: {}", e)
            }
        }
        l+=4;
    }

    {
        //Type
        options[l] = 51; l+=1;
        //Length
        options[l] = 4; l+=1;
        //Value
        let sec: u32 = 259200;
        let three_days = sec.to_le_bytes();
        options[l..l+4].copy_from_slice(&three_days);

        l+=4;
    }
    //option 1 subnet mask 255.25.255.0

    for t in &client_lock.req_list {
        match *t {
            //option 53 DHCP Msg Type :2
            53 => {
                //Type
                options[l] = *t; l+=1;
                //Length
                options[l] = 1; l+=1;
                //Value
                options[l] = DHCPOFFER; l+=1;
            }
            //option 54 svr identifier 192.168.2.1
            54 => {
                //Type
                options[l] = *t; l+=1;
                //Length
                options[l] = 4; l+=1;
                //Value
                let ip = config.get("Addr");
                if ip.is_none() {
                    println!("Key(Addr) not found");
                    break;
                }
                let addr = Ipv4Addr::from_str(&(ip.unwrap()));
                match addr {
                    Ok(ip) => {
                        options[l..l+4].copy_from_slice(&(ip.octets()));
                    }
                    Err(e) => {
                        println!("Failed to parse IP address: {}", e)
                    }
                }
                l+=4;
            }

            //option 51 ip lease time: 259200(3day)
            51 => {
                //Type
                options[l] = *t; l+=1;
                //Length
                options[l] = 4; l+=1;
                //Value
                let sec: i32 = 259200;
                let three_days = sec.to_le_bytes();
                options.copy_from_slice(&three_days);

                l+=2;
            }
            //option 1 subnet mask 255.25.255.0
            1 => {
                //Type
                options[l] = *t; l+=1;
                //Length
                options[l] = 4; l+=1;
                //Value
                let ip = Ipv4Addr::new(255,255,255,0);
                let addr = Ipv4Addr::from_str(&ip.to_string());
                match addr {
                    Ok(ip) => {
                        options[l..l+4].copy_from_slice(&(ip.octets()));
                    }
                    Err(e) => {
                        println!("Failed to parse IP address: {}", e)
                    }
                }
                l+=4;
            }
            //option 3 router 192.168.2.1
            3 => {
                //Type
                options[l] = *t; l+=1;
                //Length
                options[l] = 4; l+=1;
                //Value
                let ip = config.get("Addr");
                if ip.is_none() {
                    println!("Key(Addr) not found");
                    break;
                }
                let addr = Ipv4Addr::from_str(&(ip.unwrap()));
                match addr {
                    Ok(ip) => {
                        options[l..l+4].copy_from_slice(&(ip.octets()));
                    }
                    Err(e) => {
                        println!("Failed to parse IP address: {}", e)
                    }
                }
                l+=4;
            }
            //option 6 DNS len 8 192.168.2.1  142.166.166.166
            6 => {
                //Type
                options[l] = *t; l+=1;
                //Length
                options[l] = 4; l+=1;
                //Value
                let ip = config.get("DNS1");
                if ip.is_none() {
                    println!("Key(Addr) not found");
                    break;
                }
                let addr = Ipv4Addr::from_str(&(ip.unwrap()));
                match addr {
                    Ok(ip) => {
                        options[l..l+4].copy_from_slice(&(ip.octets()));
                    }
                    Err(e) => {
                        println!("Failed to parse IP address: {}", e)
                    }
                }
                l+=4;
            }
            //option 15 Domain name home
            15 => {
                //Type
                options[l] = *t; l+=1;
                //Value
                let value = config.get("HOST_NAME").unwrap();
                let host_name = value.as_bytes();
                let len = host_name.len();

                options[l..l+4].copy_from_slice(&host_name);

                //Length
                options[l] = len as u8; l+=1;
                l+=len;
            }
            //option 0xff 16bytes
            _ => {
            }
        }
    }
    options[l] = 255; l+=1;

    unsafe {
        let additional_data_ptr = options.as_ptr();
        ptr::copy_nonoverlapping(additional_data_ptr, buffer.as_mut_ptr().offset(HEADER_SIZE as isize), l);
    }

    return l;
}


pub fn dhcp_handle( client: &mut Arc<Mutex<Clients>>, buffer: &[u8], length: usize) {
    // let mut header;
    let mut rsp_buffer: [u8; 1024] = [0u8;1024];
    let msg_type;
    let mut len = 0;

    let ret = verify_header(client, buffer, length);
    if ret < 0 {
        println!("Verify Error Occured");
        return
    }

    {
        msg_type = client.lock().unwrap().msg_type;
    }

    // 2. Create Response
    if ret as u8 == DHCP_START_REQUEST && msg_type == DHCPDISCOVER {
        len = create_dhcp_header(client, &mut rsp_buffer, DHCP_REPLY);
        len = create_dhcp_option(client, &mut rsp_buffer, DHCPOFFER);
    }
    if ret as u8 == DHCP_START_REQUEST && msg_type == DHCPREQUEST {
        let ip = get_ip();
        println!("Allocated IP Address is: {:?}", ip);
        client.lock().unwrap().allocate_ip = ip;

        len = create_dhcp_header(client, &mut rsp_buffer, DHCP_REPLY);
        len = create_dhcp_option(client, &mut rsp_buffer, DHCPACK);
    }

    // 3. Message Send
    let client_lock = client.lock().unwrap();
    let bind = {
        format!("{}:{}", client_lock.ip, client_lock.port)
    };

    match client_lock.socket.send_to(&rsp_buffer[..len], bind) {
        Ok(bytes_sent) => {
            println!("Send {} bytes", bytes_sent);
        }
        Err(e) => {
            eprintln!("Failed to send data: {:?}", e);
        }
    }
    // let client_lock = client.lock().unwrap();
    // let dst_bind = format!("{}:{}",client_lock.ip, client_lock.port as u32);
    // header = offer_header.unwrap();
}