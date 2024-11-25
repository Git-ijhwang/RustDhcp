mod config;
mod module_sock;
mod dump;

use std::net::UdpSocket;
use std::thread;
use std::io::Result;
use config::{ConfigMap, read_conf};
use module_sock::module_sock::recv_func;
use std::sync::{Arc, RwLock};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::{Mutex, MutexGuard};

lazy_static::lazy_static! {
    pub static ref CONFIG_MAP: Arc<RwLock<ConfigMap>> = Arc::new(RwLock::new(ConfigMap::new()));
}

lazy_static::lazy_static! {
    pub static ref IPPOOL: Mutex<Vec<Ipv4Addr>> = Mutex::new(Vec::new());
}


pub fn add_ip(ip: Ipv4Addr) {
    let mut pool_lock = IPPOOL.lock().unwrap();
    pool_lock.push(ip);
}

pub fn get_ip() -> Ipv4Addr {
    let mut pool_lock = IPPOOL.lock().unwrap();
    let ip = pool_lock.pop();
    return ip.unwrap();
}

pub fn print_ip_pool () {
    let pool_lock = IPPOOL.lock().unwrap();
    for ip in pool_lock.iter() {
        println!("{}", ip);
    }
}

fn prepare_ip_pool() {
    let config = CONFIG_MAP.read().unwrap();

    let prefix = config.get("PREFIX_V4").unwrap();
    let prefix_addr = Ipv4Addr::from_str(&prefix).unwrap();

    let netmask = config.get("NETMASK_V4").unwrap();
    let netmask_addr = Ipv4Addr::from_str(&netmask).unwrap();

    let prefix_int = u32::from(prefix_addr);
    let netmask_int = u32::from(netmask_addr);
    let network_start = prefix_int & netmask_int;
    let broadcast_addr = network_start | !netmask_int;

    for ip in (network_start+1)..broadcast_addr {
        add_ip(Ipv4Addr::from(ip));
    }
}

fn main() -> Result<()>{
    // let mut config = ConfigMap::new();
     _ = read_conf();
    prepare_ip_pool();
    let config = CONFIG_MAP.read().unwrap();

    // config.
    // let src_bind =  ConfigMap::create_src_bind_addr(&config);
    let src_bind = config.create_src_bind_addr();
    if src_bind.len() <= 0 {
        println!("Read config Error");
        return Ok(());
    }

    // let svr_type = ConfigMap::get_value(&config, "Type".to_string());
    let svr_type = config.get("Type");
    if svr_type.is_none() {
        println!("Read config Error");
        return Ok(());
    }

    println!("{}", src_bind);

    let socket = UdpSocket::bind(src_bind)?;
    socket.set_nonblocking(false)?;

    // let socket_clone = socket.try_clone().expect("Failed to clone socket");
    // let (tx, rx) = channel::<String>();
    // let mut client = Arc::new(Mutex::new(Vec::<udpsock::Clients>::new()));

    let handle = thread::spawn(move || {
        println!("Create Receive Thread");
        recv_func(socket);
    });

    handle.join().unwrap();

    // send_func(socket_clone, dst_bind);

    Ok(())
}
