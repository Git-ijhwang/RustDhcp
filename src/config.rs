use std::fs::File;
use std::io::{stdin, Bytes, Result, Read};
use std::collections::HashMap;
use std::io::prelude::*;
use std::io;

#[derive(Debug)]
pub struct ConfigMap {
    data: HashMap<String, String>,
}


impl ConfigMap {
    pub fn new() -> Self {
        ConfigMap{ data: HashMap::new() }
    }

    pub fn insert(&mut self, key: String, value: String) {
        self.data.insert(key, value);
    }

    pub fn get_value(&self, target: String) -> Option<String> {
        for (key, val) in &self.data {
            if *key == target {
                return Some(val.clone());
            }
        }
        None
    }

    pub fn create_src_bind_addr(&self) -> String {
        let mut result = String::new();
        let addr = ConfigMap::get_value(self, "Addr".to_string());
        let port  = ConfigMap::get_value(self, "SrcPort".to_string());
        println!("{:?},{:?}", addr, port);

        if addr.is_some() && port.is_some() {
            result = (format!("{}:{}", addr.unwrap(), port.unwrap()));
            return result;
        }
        return result;
    }
}



pub fn read_conf(config: &mut ConfigMap ) -> Result<()>
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

            ConfigMap::insert( config, key, value);
        }
    }

    Ok(())

}

