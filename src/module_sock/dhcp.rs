use std::mem;
use std::sync::{Arc, Mutex};
use crate::module_sock::module_sock::Clients;
use super::super::dump::dump::print_hex;

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
    chaddr: [u8; 16]
}
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
            chaddr: [0u8; 16]
        }
    }

    fn verify_header(buffer:&[u8], length: usize) -> i32 {
        println!("check the dhcp header size");
        let header_size = std::mem::size_of::<DhcpHeader>();

        if length < header_size {
            println!("Received size is too small {}", length);
            return -1;
        }
        println!("size is ok");

        if let Some(header) = DhcpHeader::from_buffer(buffer) {
            if header.op != DHCP_OPERATION_CODE::DHCP_START_REQUEST as u8 {
                return 1;
            }
            if header.htype != DHCP_HTYPE::ETH_10MB as u8 && header.htype != DHCP_HTYPE::ETH_10MB_LEN as u8 {
                return 1;
            }

        } else {
            println!("Failed to parse the DHCP header.");
            return -1;
        }

        header_size as i32
    }


    /// Parse a DHCP header from a byte slice
    fn from_buffer(buffer: &[u8]) -> Option<Self> {
        let header_size = mem::size_of::<DhcpHeader>();
        if buffer.len() < header_size {
            return None;
        }

        // Use unsafe to transmute the buffer into a DhcpHeader
        unsafe {
            Some(std::ptr::read(buffer.as_ptr() as *const DhcpHeader))
        }
    }
}

fn make_dhcp_response() {}
fn send_dhcp_msg(){}


/// DHCP OFFER 메시지 생성
fn create_dhcp_offer( client: &mut Arc<Mutex<Clients>>, buffer: &[u8] ) -> Option<DhcpHeader> {
    // let header: Option<DhcpHeader> = DhcpHeader::from_buffer(buffer);

    if let Some(header) = DhcpHeader::from_buffer(buffer) {
    {
        println!("{:#?}", header);

        let xid = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
        // let xid_bytes = xid.to_be_bytes(); // u32를 [u8; 4]로 변환
        // print_hex(&xid_bytes, mem::size_of::<u32>());

        client.lock().unwrap().tranxid = xid;
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
        })

    }else {
        None
    }
}


pub fn dhcp_handle( client: &mut Arc<Mutex<Clients>>, buffer: &[u8], length: usize) {
    let mut header;
    let ret = DhcpHeader::verify_header(buffer, length);
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

    let dst_bind = format!("{}:{}",client.arc().u, client.port as u32);
    header = offer_header.unwrap();

}