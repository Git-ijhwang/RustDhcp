mod config;
mod module_sock;
mod dump;

use std::net::UdpSocket;
use std::thread;
use std::io::Result;
use config::{ConfigMap, read_conf};
use module_sock::module_sock::recv_func;
use std::sync::{Arc, RwLock};

lazy_static::lazy_static! {
    pub static ref CONFIG_MAP: Arc<RwLock<ConfigMap>> = Arc::new(RwLock::new(ConfigMap::new()));
}

fn main() -> Result<()>{
    // let mut config = ConfigMap::new();
     _ = read_conf();
    let mut config = CONFIG_MAP.read().unwrap();

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
    println!("After Udpsock bind()");
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
