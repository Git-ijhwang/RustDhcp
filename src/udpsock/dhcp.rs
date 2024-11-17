use std::fs::File;
use std::mem;
use std::io::{stdin, Bytes, Result, Read};
use std::collections::HashMap;
use std::io::prelude::*;
use std::io;
use std::sync::{ Arc, Mutex};

#[derive(Debug)]
struct DhcpHeader {
    op: u8,
    htype: u8,
    hlen: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: u16,
    ciaddr: u32,
    yiaddr: u32,
    siaddr: u32,
    giaddr: u32,
    chaddr: [u8; 16]
}
enum DHCP_OPERATION_CODE {
    DHCP_START_REQUEST = 1,
    DHCP_START_REPLY,
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
    fn verify_header( client:Arc<Mutex<super::Clients>>, buffer:&[u8], length: usize) -> i32 {
        let header_size = std::mem::size_of::<DhcpHeader>();

        if length < header_size {
            println!("Received size is too small {}", length);
            return -1;
        }

        if let Some(header) = DhcpHeader::from_buffer(buffer) {
            if header.op == DHCP_OPERATION_CODE::DHCP_START_REQUEST as u8 {

            }
            if header.htype != DHCP_HTYPE::ETH_10MB as u8 && header.htype != DHCP_HTYPE::ETH_10MB_LEN as u8 {

            }

            client.lock().unwrap().tranxid = header.xid;
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

pub fn dhcp_handle(
    client:Arc<Mutex<super::Clients>>,
    buffer: &[u8], length: usize) {

    let len = DhcpHeader::verify_header(client, buffer, length);
    if let Some(header) = DhcpHeader::from_buffer(buffer) {
        println!("{:#?}", header);
        println!("op: {}", header.op);
        println!("htype: {}", header.htype);
        println!("hlen: {}", header.hlen);
        println!("hops: {}", header.hops);
        println!("xid: {}", header.xid);
        println!("secs: {}", header.secs);
        println!("flags: {}", header.flags);
        println!("ciaddr: {}", header.ciaddr);
    }
}