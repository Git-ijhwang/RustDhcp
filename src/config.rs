use std::fs::File;
use std::io::Result;
use std::collections::HashMap;
use std::io::prelude::*;
use std::io;
use std::sync::{Arc, RwLock};
use crate::CONFIG_MAP;

#[derive(Debug)]
pub struct ConfigMap {
    data: HashMap<String, String>,
}


impl ConfigMap
{
    pub fn new() -> Self {
        Self{ 
            data: HashMap::new()
        }
    }

    pub fn insert(&mut self, key: String, value: String) {
        self.data.insert(key, value);
    }

    pub fn get(&self, target: &str) -> Option<String> {
        self.data.get(target).cloned()
    }

    pub fn create_src_bind_addr(&self) -> String {
        let mut result = String::new();
        let addr = ConfigMap::get(self, "Addr");
        let port  = ConfigMap::get(self, "SrcPort");
        println!("{:?},{:?}", addr, port);

        if addr.is_some() && port.is_some() {
            result = format!("{}:{}", addr.unwrap(), port.unwrap());
            return result;
        }
        return result;
    }
}


pub fn read_conf( ) -> Result<()>
{
    let file = File::open("src/config")?;

    let reader = io::BufReader::new(file);

    for line in reader.lines() {
        let mut configline = line?;

        //Skip the comment line with '#'
        let position = configline.trim().find('#');
        if position == Some(0) {
            continue;
        }

        //Remove string after '#'
        if let Some(pos) = configline.find('#') {
            configline = configline[..pos].trim().to_string();
        }
        println!("{configline}");

        //Key, Value pair
        if let Some(pos) = configline.find('=') {
            let key = configline[..pos].trim().to_string();
            let value = configline[pos+1..].trim().to_string();

            let mut config = CONFIG_MAP.write().unwrap();
            config.insert(key, value);
        }
    }

    Ok(())

}

