mod config;
mod module_sock;
mod dump;

use std::net::UdpSocket;
use std::thread;
use std::result::Result;
use config::{ConfigMap, read_conf};
use module_sock::module_sock::recv_func;
use std::sync::{Arc, RwLock};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::{Mutex, MutexGuard};
use log::{debug, error, info, trace, warn};
use std::time::SystemTime;

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


fn setup_logger(log: &str) -> Result<(), fern::InitError> {

    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{} {} {}] {}",
                humantime::format_rfc3339_seconds(SystemTime::now()),
                record.level(),
                record.target(),
                message
            ))
        })
        .level(log::LevelFilter::Debug)
        .chain(std::io::stdout())
        .chain(fern::log_file(log)?)
        .apply()?;

    Ok(())
}

fn socket_create (src_bind: String) -> Result<UdpSocket, String> {
    let socket = UdpSocket::bind(&src_bind).map_err(|e| {
        format!("UDP Socket binding Error on {}: {}", src_bind, e)
    })?;

    socket.set_nonblocking(false).map_err(|e| {
        format!("Failed to set non-blocking mode: {}", e)
    })?;

    Ok(socket)
}

fn main() -> Result<(),()>
{
    /* Read Config */
    _ = read_conf();
    let config = CONFIG_MAP.read().unwrap();

    /* Logging Setup */
    if setup_logger(&config.get("Log").unwrap()).is_err() {
        println!("Loggin Setting Error.");
        return Err(());
     }

    /* IP Pool set-up */
    info!("IP Pool Set up");
    prepare_ip_pool();

    // Create Binding
    let src_bind = config.create_src_bind_addr();
    info!("Created Binding for {}", src_bind);
    if src_bind.len() <= 0 {
        println!("Read config Error");
        return Err(());
    }

    let svr_type = config.get("Type");
    if svr_type.is_none() {
        println!("Read config Error");
        return Err(());
    }

    let socket = socket_create(src_bind);
    if socket.is_err() {
        println!("{}", socket.unwrap_err());
        return Err(());
    }

    let socket = socket.unwrap();

    let handle = thread::spawn(move || {
        println!("Create Receive Thread");
        recv_func(socket);
    });

    handle.join().unwrap();

   Ok(())
}
