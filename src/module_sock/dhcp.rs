use core::str;
use std::mem;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use crate::module_sock::module_sock::Clients;
use super::super::dump::dump::print_hex;
use std::mem::size_of;
use byteorder::{ByteOrder, BigEndian};


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
    xid: u32,       //Transaction ID. Filled by Client
    secs: u16,      //Seconds elapsed since client began address. Filled by Client
    flags: u16,     //Flag
    ciaddr: u32,    //Client IP Address
    yiaddr: u32,    //Your(Client) IP address
    siaddr: u32,    //Server IP Address
    giaddr: u32,    //Relay agent IP Address
    chaddr: [u8; 16], //Client Mac Address
    sname: [u8; 64], //Server host name
    file: [u8; 128], //Boot file name
}

impl DhcpHeader {

    pub fn new() -> Self {
        DhcpHeader {
            op: 0,
            htype: 0,
            hlen: 0,
            hops: 0,
            xid: 02,
            secs: 06,
            flags: 06,
            ciaddr: 02,
            yiaddr: 02,
            siaddr: 02,
            giaddr: 02,
            chaddr: [0u8; 16],
            sname: [0u8; 64],
            file: [0u8; 128],
        }
    }

    fn parse_option_field (client: &mut Arc<Mutex<Clients>>, buffer:&[u8], len: usize) {
        let mut msg_type = 0;
        let mut pos  = 4; // 4 octet magic cookie
        let mut t = 0;
        let mut l = 0;
        let length = len - 4;

        // println!("Parse Option Field");
        loop {
            t = buffer[pos];
            // println!("Type: {:02} [0x{:02x}]", t, t); //Type
            pos += 1;

            if t == 255 {
                println!("End of Option");
                break;
            }

            l = buffer[pos] as usize;
            // println!("Length: {} bytes", l); //Length
            pos += 1;

            let mut client_lock = client.lock().unwrap();
            match t {
                12 => {
                    println!("Host Name");
                    match str::from_utf8(&buffer[pos..pos+l]) {
                        Ok(string) => client_lock.hostname = string.to_string(),
                        Err(e) => break,
                    }

                },
                50 => {
                    println!("Request IP Address");
                    client_lock.reqip = Ipv4Addr::new(buffer[pos], buffer[pos+1],
                    buffer[pos+2], buffer[pos+3])
                },
                51 => {
                    println!("IP Address Lease Time");
                    let slice:[u8; 4] = buffer[pos..pos+l].try_into().expect("testasdf");
                    client_lock.lease_time = u32::from_be_bytes(slice);
                },
                53 => {
                    println!("DHCP Message Type (Request)");
                    msg_type = buffer[pos];
                },
                55 => {
                    let slice = &buffer[pos..pos+l];
                    let len = client_lock.req_list.len().min(slice.len());
                    client_lock.req_list.fill(0);
                    println!("Parameter Request List");
                    // match u8::from_be_bytes(slice) {}
                    client_lock.req_list[..len].copy_from_slice(&slice[..len]);
                    // .try_into().expect("asfd");
                },
                57 => {
                    let slice:[u8; 2] = buffer[pos..pos+l].try_into().expect("testasdf");
                    let size = u16::from_be_bytes(slice);
                    println!("Maximum DHCP Message Size {}", size);
                },
                61 => {
                    println!("Client Identifier");
                    let slice = &buffer[pos..pos+l];
                    let len = client_lock.req_list.len().min(slice.len());
                    client_lock.req_list.fill(0);
                    // let slice:[u8; l] = buffer[pos..pos+l].try_into().expect("testasdf");
                    client_lock.cid[..len].copy_from_slice(&slice[..len]);
                    // buffer[pos..pos+l].try_into().expect("asfd");
                    // client_lock.req_list[..len].copy_from_slice(&slice[..len]);
                },
                255 =>println!("Opeion End"),
                _ => println!("Unknown type {}", t)
            }

            pos += l;
            // print_hex(&buffer[pos..pos+l], l);

            if pos >= length {
                break;
            }
        }
        println!("{:#?}", client.lock().unwrap());

    }


    fn verify_header( client: &mut Arc<Mutex<Clients>>, buffer:&[u8], length: usize) -> i32 {
        println!("check the dhcp header size");
        let header_size = size_of::<DhcpHeader>();

        if length < header_size {
            println!("Received size is too small {}", length);
            return -1;
        }
        println!("size {}bytes is ok", header_size);

        if let Some(header) = DhcpHeader::from_buffer(buffer) {
            println!("{:p}", &header);
            
            let header_ptr = &header as *const DhcpHeader as *const u8;
            let header_bytes = unsafe { std::slice::from_raw_parts(header_ptr, std::mem::size_of::<DhcpHeader>()) };

            print_hex(&header_bytes[..header_size], header_size);
            if header.op != DHCP_OPERATION_CODE::DHCP_START_REQUEST as u8 {
                println!("Operation Code: 0x{:02x}", header.op);
                return 1;
            }
            if header.htype != DHCP_HTYPE::ETH_10MB as u8 && header.htype != DHCP_HTYPE::ETH_10MB_LEN as u8 {
                println!("Hardware type: 0x{:02x}", header.htype);
                return 1;
            }

            let slice = &buffer[4..8];
            client.lock().unwrap().tranxid.copy_from_slice(slice);
            // client_lock.cid[..len].copy_from_slice(&slice[..len]);

            Self::parse_option_field(client, &buffer[header_size..], length-header_size);

        } else {
            println!("Failed to parse the DHCP header.");
            return -1;
        }

        header_size as i32
    }

  
    /// Parse a DHCP header from a byte slice
    fn from_buffer(buffer: &[u8]) -> Option<Self> {
        let header_size = mem::size_of::<DhcpHeader>();
        // if buffer.len() < header_size {
        //     return None;
        // }

        // Use unsafe to transmute the buffer into a DhcpHeader
        // unsafe {
        //     Some(std::ptr::read(buffer.as_ptr() as *const DhcpHeader))
        // }
        Some(Self {
            op: buffer[0],
            htype: buffer[1],
            hlen: buffer[2],
            hops: buffer[3],
            xid: BigEndian::read_u32(&buffer[4..8]),
            secs: BigEndian::read_u16(&buffer[8..10]),
            flags: BigEndian::read_u16(&buffer[10..12]),
            ciaddr: BigEndian::read_u32(&buffer[12..16]),
            yiaddr: BigEndian::read_u32(&buffer[16..20]),
            siaddr: BigEndian::read_u32(&buffer[20..24]),
            giaddr: BigEndian::read_u32(&buffer[24..28]),
            chaddr: buffer[28..44].try_into().unwrap_or([0; 16]),
            sname: buffer[44..108].try_into().unwrap_or([0; 64]),
            file: buffer[108..236].try_into().unwrap_or([0; 128]),
        })
    }
}

fn make_dhcp_response() {}
fn send_dhcp_msg(){}


/// DHCP OFFER 메시지 생성
fn create_dhcp_offer( client: &mut Arc<Mutex<Clients>>, buffer: &[u8] ) -> Option<DhcpHeader> {
    // let header: Option<DhcpHeader> = DhcpHeader::from_buffer(buffer);

    if let Some(header) = DhcpHeader::from_buffer(buffer) {
    {
        // println!("{:#?}", header);

        // let xid = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
        // let xid_bytes = xid.to_be_bytes(); // u32를 [u8; 4]로 변환

        // println!("Saved xid: {:#?}", client.lock().unwrap().tranxid);
    }


        Some( DhcpHeader {
            op: DHCP_OPERATION_CODE::DHCP_REPLY as u8,
            htype: header.htype,
            hlen: header.hlen,
            hops: 0,
            xid: header.xid, // 트랜잭션 ID 유지
            secs: 0,
            flags: 0,
            ciaddr: 0,
            yiaddr: 0xC0A80101, // Offer할 IP 예시 (192.168.1.1)
            siaddr: 0xC0A80101, // 서버 IP 예시
            giaddr: 0,
            chaddr: header.chaddr,
            sname: [0u8; 64],
            file: [0u8; 128],
        })

    }else {
        None
    }
}


pub fn dhcp_handle( client: &mut Arc<Mutex<Clients>>, buffer: &[u8], length: usize) {
    let mut header;

    let ret = DhcpHeader::verify_header(client, buffer, length);
    if ret < 0 {
        println!("verify occured");
        return
    }

    // 2. 응답 생성
    let mut offer_header = create_dhcp_offer(client, &buffer);
    if offer_header.is_none() {
        println!("error in create dhcp ack message");
        return
    }

    let client_lock = client.lock().unwrap();
    let dst_bind = format!("{}:{}",client_lock.ip, client_lock.port as u32);
    header = offer_header.unwrap();

}