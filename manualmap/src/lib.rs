#![no_std]
#![no_main]

extern crate alloc;

#[macro_use]
extern crate litcrypt2;
use_litcrypt!();

use core::ptr;
use core::{cell::UnsafeCell, ffi::c_void};
use core::fmt::Write;
use alloc::{string::{String, ToString}, vec::Vec};
use alloc::collections::BTreeMap;
use data::{CloseHandle, GetCurrentProcess, GetProcessHeap, HeapFree, ImageBaseRelocation, ImageFileHeader, ImageImportDescriptor, ImageOptionalHeader32, ImageOptionalHeader64, ImageSectionHeader, PeMetadata, MEM_COMMIT, MEM_RESERVE, OSVERSIONINFOW, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE, PVOID, SECTION_MEM_EXECUTE, SECTION_MEM_READ, SECTION_MEM_WRITE};

/// Retrieves the PE headers from the specified module.
///
/// It will return either a data::PeMetada struct containing the PE
/// metadata or a String with a descriptive error message.
///
/// # Examples
///
/// ```
/// use std::fs;
///
/// let file_content = utils::read_file(r"c:\windows\system32\ntdll.dll")?;
/// let file_content_ptr = file_content.as_ptr();
/// let result = manualmap::get_pe_metadata(file_content_ptr, false);
/// ```
pub fn get_pe_metadata (module_ptr: *const u8, check_signature: bool) -> Result<PeMetadata,String>
{
    let mut pe_metadata= PeMetadata::default();

    unsafe 
    {
        let e_lfanew = *((module_ptr as usize + 0x3C) as *const u32);
        pe_metadata.pe = *((module_ptr as usize + e_lfanew as usize) as *const u32);

        if pe_metadata.pe != 0x4550 && check_signature {
            return Err(lc!("[x] Invalid PE signature."));
        }

        pe_metadata.image_file_header = *((module_ptr as usize + e_lfanew as usize + 0x4) as *mut ImageFileHeader);

        let opt_header: *const u16 = (module_ptr as usize + e_lfanew as usize + 0x18) as *const u16; 
        let pe_arch = *(opt_header);

        if pe_arch == 0x010B
        {
            pe_metadata.is_32_bit = true;
            let opt_header_content: *const ImageOptionalHeader32 = core::mem::transmute(opt_header);
            pe_metadata.opt_header_32 = *opt_header_content;
        }
        else if pe_arch == 0x020B 
        {
            pe_metadata.is_32_bit = false;
            let opt_header_content: *const ImageOptionalHeader64 = core::mem::transmute(opt_header);
            pe_metadata.opt_header_64 = *opt_header_content;
        } 
        else {
            return Err(lc!("[x] Invalid magic value."));
        }

        let mut sections: Vec<ImageSectionHeader> = Vec::new();

        for i in 0..pe_metadata.image_file_header.number_of_sections
        {
            let section_ptr = (opt_header as usize + pe_metadata.image_file_header.size_of_optional_header as usize + (i * 0x28) as usize) as *const u8;
            let section_ptr: *const ImageSectionHeader = core::mem::transmute(section_ptr);
            sections.push(*section_ptr);
        }

        pe_metadata.sections = sections;

        Ok(pe_metadata)
    }
}

/// Manually maps a PE from disk to the memory of the current process.
///
/// If the clean_headers parameters is set to true, the mapped pe's dos header will be removed during the
/// mapping process. Otherwise, the dos header will be kept untouched.
/// 
/// The third parameter determines whether TLS callbacks are executed (true) or not (false).
/// 
/// It will return either a pair (PeMetadata,usize) containing the mapped PE
/// metadata and its base address or a String with a descriptive error message.
///
/// # Examples
///
/// ```
/// let ntdll = manualmap::read_and_map_module(r"c:\windows\system32\ntdll.dll", true, false);
///
/// match ntdll {
///     Ok(x) => if x.1 != 0 { utils::println!("The base address of ntdll.dll is 0x{:X}.", x.1);},
///     Err(e) => {utils::println!("{}", e);},      
/// }
/// ```
pub fn read_and_map_module (filepath: &str, clean_dos_header: bool, run_callbacks: bool) -> Result<(PeMetadata,usize), String> 
{
    let file_content =  utils::read_file(filepath)?;
    let file_content_ptr = file_content.as_ptr() as *mut _;
    let result = manually_map_module(file_content_ptr, clean_dos_header, run_callbacks)?;

    unsafe 
    {
        for i in 0..file_content.len() {
            *(file_content_ptr.add(i)) = 0u8;
        }

        // Since this Vec's memory has been allocated with HeapAlloc instead of _aligned_malloc
        // the Drop trait can't be executed. Instead, the buffer has to be freed manually.
        core::mem::forget(file_content); 
        let process_heap = GetProcessHeap();
        let _ = HeapFree(process_heap, 0, file_content_ptr as _);

        Ok(result)
    }

}

/// Manually maps a PE into the current process.
///
/// If the clean_headers parameters is set to true, the mapped pe's dos header will be removed during the
/// mapping process. Otherwise, the dos header will be kept untouched.
/// 
/// The third parameter determines whether TLS callbacks are executed (true) or not (false).
/// 
/// It will return either a pair (PeMetadata,usize) containing the mapped PE
/// metadata and its base address or a String with a descriptive error message.
///
/// # Examples
///
/// ```
/// let file_content = utils::read_file(r"c:\windows\system32\ntdll.dll")?;
/// let file_content_ptr = file_content.as_ptr();
/// let result = manualmap::manually_map_module(file_content_ptr, true, false);
/// ```
pub fn manually_map_module (file_ptr: *const u8, clean_dos_headers: bool, run_callbacks: bool) -> Result<(PeMetadata,usize), String> 
{
    let pe_info = get_pe_metadata(file_ptr, false)?;
    if (pe_info.is_32_bit && (size_of::<usize>() == 8)) || (!pe_info.is_32_bit && (size_of::<usize>() == 4)) {
        return Err(lc!("[x] The module architecture does not match the process architecture.".to_string));
    }

    let dwsize;
    if pe_info.is_32_bit {
        dwsize = pe_info.opt_header_32.size_of_image as usize;
    } else {
        dwsize = pe_info.opt_header_64.size_of_image as usize;
    }

    unsafe 
    {
        let handle = GetCurrentProcess();
        let a = usize::default();
        let base_address: *mut PVOID = core::mem::transmute(&a);
        let zero_bits = 0 as usize;
        let size: *mut usize = core::mem::transmute(&dwsize);

        let ret = dinvoke::nt_allocate_virtual_memory(handle, base_address, zero_bits, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        let _r = CloseHandle(handle);

        if ret != 0 {
            return Err(lc!("[x] Error allocating memory."));
        }

        let image_ptr = *base_address;

        map_module_to_memory(file_ptr, image_ptr, &pe_info)?;
        relocate_module(&pe_info, image_ptr);
        rewrite_module_iat(&pe_info, image_ptr)?;
        if clean_dos_headers {
            clean_dos_header(image_ptr);
        }

        set_module_section_permissions(&pe_info, image_ptr)?;
        add_runtime_table(&pe_info, image_ptr);
        if run_callbacks {
            run_tls_callbacks(&pe_info, image_ptr);
        }

        Ok((pe_info,image_ptr as usize))

    }

}

/// Maps a module to a valid memory space in the current process.
///
/// The parameters required are a vector with the module content, the base address where the module should be
/// mapped and the module's metadata.
fn map_module_to_memory(module_ptr: *const u8, image_ptr: *mut c_void, pe_info: &PeMetadata) -> Result<(),String>
{
    if (pe_info.is_32_bit && (size_of::<usize>() == 8)) || (!pe_info.is_32_bit && (size_of::<usize>() == 4)) {
        return Err(lc!("[x] The module architecture does not match the process architecture."));
    }

    let nsize;
    if pe_info.is_32_bit {
        nsize = pe_info.opt_header_32.size_of_headers as usize;
    } else {
        nsize = pe_info.opt_header_64.size_of_headers as usize;
    }

    unsafe 
    {   

        let handle = GetCurrentProcess();
        let base_address: *mut c_void = core::mem::transmute(image_ptr);
        let buffer: *mut c_void = core::mem::transmute(module_ptr);
        let written: usize = 0;
        let bytes_written: *mut usize = core::mem::transmute(&written);
        let ret = dinvoke::nt_write_virtual_memory(handle, base_address, buffer, nsize, bytes_written);

        if ret != 0
        {
            let _r = CloseHandle(handle);
            return Err(lc!("[x] Error writing PE headers to the allocated memory."));
        }

        for section in &pe_info.sections
        {
            let section_base_ptr = (image_ptr as usize + section.virtual_address as usize) as *mut u8;
            let section_content_ptr = (module_ptr as usize + section.pointer_to_raw_data as usize) as *mut u8;          

            let base_address: *mut c_void = core::mem::transmute(section_base_ptr);
            let buffer: *mut c_void = core::mem::transmute(section_content_ptr);
            let nsize = section.size_of_raw_data as usize;
            let bytes_written: *mut usize = core::mem::transmute(&written);
            let ret = dinvoke::nt_write_virtual_memory(handle, base_address, buffer, nsize, bytes_written);
            let _r = CloseHandle(handle);

            if ret != 0 || *bytes_written != nsize {
                return Err(lc!("[x] Failed to write PE sections to the allocated memory."))
            }
        }

        Ok(())
    }
}

/// Relocates a module in memory.
///
/// The parameters required are the module's metadata information and a
/// pointer to the base address where the module is mapped in memory.
fn relocate_module(pe_info: &PeMetadata, image_ptr: *mut c_void) 
{
    unsafe {

        let module_memory_base: *mut usize = core::mem::transmute(image_ptr);
        let image_data_directory;
        let image_delta: isize;
        if pe_info.is_32_bit 
        {
            image_data_directory = pe_info.opt_header_32.datas_directory[5]; // BaseRelocationTable
            image_delta = module_memory_base as isize - pe_info.opt_header_32.image_base as isize;
        }
        else 
        {
            image_data_directory = pe_info.opt_header_64.datas_directory[5]; // BaseRelocationTable
            image_delta = module_memory_base as isize - pe_info.opt_header_64.image_base as isize;
        }

        let mut reloc_table_ptr = (module_memory_base as usize + image_data_directory.virtual_address as usize) as *mut i32;
        let mut next_reloc_table_block = -1;

        while next_reloc_table_block != 0 
        {
            let ibr: *mut ImageBaseRelocation = core::mem::transmute(reloc_table_ptr);
            let image_base_relocation = *ibr;
            let reloc_count: isize = (image_base_relocation.size_of_block as isize - size_of::<ImageBaseRelocation>() as isize) / 2;

            for i in 0..reloc_count
            {
                let reloc_entry_ptr = (reloc_table_ptr as usize + size_of::<ImageBaseRelocation>() as usize + (i * 2) as usize) as *mut u16;
                let reloc_value = *reloc_entry_ptr;

                let reloc_type = reloc_value >> 12;
                let reloc_patch = reloc_value & 0xfff;

                if reloc_type != 0
                {
                    
                    if reloc_type == 0x3
                    {
                        let patch_ptr = (module_memory_base as usize + image_base_relocation.virtual_address as usize + reloc_patch as usize) as *mut i32;
                        let original_ptr = *patch_ptr;
                        let patch = original_ptr + image_delta as i32;
                        *patch_ptr = patch;
                    }
                    else 
                    {
                        let patch_ptr = (module_memory_base as usize + image_base_relocation.virtual_address as usize + reloc_patch as usize) as *mut isize;
                        let original_ptr = *patch_ptr;
                        let patch = original_ptr + image_delta as isize;
                        *patch_ptr = patch;
                    }
                }
            }

            reloc_table_ptr = (reloc_table_ptr as usize + image_base_relocation.size_of_block as usize) as *mut i32;
            next_reloc_table_block = *reloc_table_ptr;

        }


    }
}

/// Rewrites the IAT of a manually mapped module.
///
/// The parameters required are the module's metadata information and a
/// pointer to the base address where the module is mapped in memory.
fn rewrite_module_iat(pe_info: &PeMetadata, image_ptr: *mut c_void) -> Result<(),String> 
{
    unsafe 
    {
        let module_memory_base: *mut usize = core::mem::transmute(image_ptr);
        let image_data_directory;
        if pe_info.is_32_bit 
        {
            image_data_directory = pe_info.opt_header_32.datas_directory[1]; // ImportTable
        } else {
            image_data_directory = pe_info.opt_header_64.datas_directory[1]; // ImportTable
        }

        if image_data_directory.virtual_address == 0  {
            return Ok(()); // No hay import table
        }

        let import_table_ptr = (module_memory_base as usize + image_data_directory.virtual_address as usize) as *mut usize;

        let mut version_info: OSVERSIONINFOW = core::mem::zeroed();
        version_info.dw_osversion_info_size = 276;
        let ret = dinvoke::rtl_get_version(&mut version_info);
        let version = version_info.dw_major_version.to_string();
        let mut api_set_dict: BTreeMap<String,String>= BTreeMap::new();
        if ret == 0 && version >= "10".to_string() {
            api_set_dict = dinvoke::get_api_mapping();
        }

        let mut counter = 0;
        let mut image_import_descriptor_ptr = (import_table_ptr as usize + size_of::<ImageImportDescriptor>() as usize * counter) as *mut ImageImportDescriptor;
        let mut image_import_descriptor = *image_import_descriptor_ptr;

        while image_import_descriptor.name != 0
        {
            let mut dll_name = "".to_string();
            let mut c: char = ' ';
            let mut ptr = (module_memory_base as usize + image_import_descriptor.name as usize) as *mut u8;
            while c != '\0'
            {
                c = *ptr as char;
                if c != '\0'
                {
                    dll_name.push(c);
                    ptr = ptr.add(1);
                }
            }

            if dll_name == "" {
                return Ok(());
            }
            else 
            {
                let mut lookup_key = String::new();
                let _ = write!(lookup_key, "{}{}", &dll_name[..dll_name.len() - 6], ".dll");

                if (version >= 10.to_string() && (dll_name.starts_with("api-") || dll_name.starts_with("ext-"))) &&  api_set_dict.contains_key(&lookup_key)
                {
                    let key = match api_set_dict.get(&lookup_key) {
                        Some(x) => x.to_string(),
                        None => "".to_string(),
                    };

                    if key.len() > 0 {
                        dll_name = key.to_string();
                    }
                }

                let mut module_handle = dinvoke::get_module_base_address(&dll_name) as usize;

                if module_handle == 0
                {

                    module_handle = dinvoke::load_library_a(&dll_name) as usize;

                    if module_handle == 0 
                    {
                        let mut msg = String::new();
                        let _ = write!(msg, "{}: {}", lc!("[x] Unable to find the specified module"), dll_name);
                        return Err(msg); 
                    }
                }

                if pe_info.is_32_bit
                {
                    let mut i: isize = 0;

                    loop 
                    {
                        let image_thunk_data = (module_memory_base as usize + image_import_descriptor.anonymous as usize 
                            + i as usize * size_of::<u32>() as usize) as *mut u32;
                        let image_thunk_data = *image_thunk_data;
                        let ft_itd = (module_memory_base as usize + image_import_descriptor.first_thunk as usize +
                            i as usize * size_of::<u32>() as usize) as *mut i32;

                        if image_thunk_data == 0 {
                            break;
                        }

                        if image_thunk_data < 0x80000000
                        {
                            let mut imp_by_name_ptr = (module_memory_base as usize + image_thunk_data as usize + size_of::<u16>() as usize) as *mut u8;
                            let mut import_name: String = "".to_string();
                            let mut c: char = ' ';
                            while c != '\0'
                            {
                                c = *imp_by_name_ptr as char;
                                if c != '\0' {
                                    import_name.push(c);
                                }

                                imp_by_name_ptr = imp_by_name_ptr.add(1);
                            }

                            let func_ptr = dinvoke::get_function_address(module_handle, &import_name);
                            *ft_itd = func_ptr as i32;
                        }
                        else 
                        {
                            let f_ordinal = (image_thunk_data & 0xFFFF) as u32;
                            let func_ptr = dinvoke::get_function_address_by_ordinal(module_handle, f_ordinal);
                            let func_ptr = func_ptr as *mut i32;
                            *ft_itd = func_ptr as i32;
                        }

                        i = i + 1;
                    }
                }
                else 
                {
                    let mut i: isize = 0;

                    loop 
                    {
                        let image_thunk_data = (module_memory_base as u64 + image_import_descriptor.anonymous as u64 
                            + i as u64 * size_of::<u64>() as u64) as *mut u64;
                        let image_thunk_data = *image_thunk_data;
                        let ft_itd = (module_memory_base as u64 + image_import_descriptor.first_thunk as u64 +
                            i as u64 * size_of::<u64>() as u64) as *mut isize;
                        

                        if image_thunk_data == 0 {
                            break;
                        }

                        if image_thunk_data < 0x8000000000000000
                        {
                            let mut imp_by_name_ptr = (module_memory_base as u64 + image_thunk_data as u64 + size_of::<u16>() as u64) as *mut u8;
                            let mut import_name: String = "".to_string();
                            let mut c: char = ' ';
                            while c != '\0'
                            {
                                c = *imp_by_name_ptr as char;
                                if c != '\0' {
                                    import_name.push(c);
                                }

                                imp_by_name_ptr = imp_by_name_ptr.add(1);
                            }

                            let func_ptr = dinvoke::get_function_address(module_handle, &import_name) as *mut isize;
                            *ft_itd = func_ptr as isize;
                        }
                        else 
                        {
                            let f_ordinal = (image_thunk_data & 0xFFFF) as u32;
                            let func_ptr = dinvoke::get_function_address_by_ordinal(module_handle, f_ordinal);
                            *ft_itd = func_ptr as isize;
                        }

                        i = i + 1;
                    }
                }
  
            }

            counter = counter + 1;
            image_import_descriptor_ptr = (import_table_ptr as usize + size_of::<ImageImportDescriptor>() as usize * counter) as *mut ImageImportDescriptor;
            image_import_descriptor = *image_import_descriptor_ptr;

        }

        Ok(())
    }
}

// This method is reponsible for cleaning IOCs that may reveal the pressence of a 
// manually mapped PE in a private memory region. It will remove PE magic bytes,
// DOS header and DOS stub.
fn clean_dos_header (image_ptr: *mut c_void) 
{
    unsafe
    {
        let mut base_addr = image_ptr as *mut u8;
        let pe_header = image_ptr as isize + 0x3C;
        while (base_addr as isize) < pe_header
        {
            *base_addr = 0;
            base_addr = base_addr.add(1);            
        }
        base_addr = base_addr.add(4);

        let e_lfanew = *((image_ptr as usize + 0x3C) as *const u32);
        let pe = image_ptr as isize + e_lfanew as isize;

        while (base_addr as isize) < pe
        {
            *base_addr = 0;
            base_addr = base_addr.add(1);            
        }

        let pe = pe as *mut u16;
        *pe = 0;
    }
}

fn add_runtime_table(pe_info: &PeMetadata, image_ptr: *mut c_void) 
{
    unsafe 
    {
        for section in &pe_info.sections
        {   
            let s = core::str::from_utf8(&section.name).unwrap();
            if s.contains(".pdata")
            {
                let entry_count = (section.size_of_raw_data / 12) as i32; // 12 = size_of RUNTIME_FUNCTION

                let func: data::RtlAddFunctionTable;
                let _ret: Option<bool>;                
                let k32 = dinvoke::get_module_base_address(&lc!("kernel32.dll"));
                let function_table_addr: usize = image_ptr as usize + section.virtual_address as usize;
                dinvoke::dynamic_invoke!(k32,&lc!("RtlAddFunctionTable"),func,_ret,function_table_addr,entry_count,image_ptr as usize);
            }
        }
    }

}

/// Sets correct module section permissions for a manually mapped module.
///
/// The parameters required are the module's metadata information and a
/// pointer to the base address where the module is mapped in memory.
fn set_module_section_permissions(pe_info: &PeMetadata, image_ptr: *mut c_void) -> Result<(),String> 
{
    unsafe 
    {
        let base_of_code;

        if pe_info.is_32_bit {
            base_of_code = pe_info.opt_header_32.base_of_code as usize;
        } else {
            base_of_code = pe_info.opt_header_64.base_of_code as usize;
        }

        let handle = GetCurrentProcess();
        let base_address: *mut PVOID = core::mem::transmute(&image_ptr);
        let s: UnsafeCell<isize> = isize::default().into();
        let size: *mut usize = core::mem::transmute(s.get());
        *size = base_of_code;
        let o = u32::default();
        let old_protection: *mut u32 = core::mem::transmute(&o);
        let _ret = dinvoke::nt_protect_virtual_memory(handle, base_address, size, PAGE_READONLY, old_protection);
       
        for section in &pe_info.sections
        {
            let is_read = (section.characteristics & SECTION_MEM_READ) != 0;
            let is_write = (section.characteristics & SECTION_MEM_WRITE) != 0;
            let is_execute = (section.characteristics & SECTION_MEM_EXECUTE) != 0;
            let new_protect: u32;

            if is_read & !is_write & !is_execute {
                new_protect = PAGE_READONLY;
            }
            else if is_read & is_write & !is_execute {
                new_protect = PAGE_READWRITE;
            } 
            else if is_read & is_write & is_execute {
                new_protect = PAGE_EXECUTE_READWRITE;
            }
            else if is_read & !is_write & is_execute {
                new_protect = PAGE_EXECUTE_READ;
            }
            else if !is_read & !is_write & is_execute {
                new_protect = PAGE_EXECUTE;
            }
            else
            {
                return Err(lc!("[x] Unknown section permission."));
            }

            let address: *mut c_void = (image_ptr as usize + section.virtual_address as usize) as *mut c_void;
            let base_address: *mut PVOID = core::mem::transmute(&address);
            *size = section.misc as usize;
            let o = u32::default();
            let old_protection: *mut u32 = core::mem::transmute(&o);
            let ret = dinvoke::nt_protect_virtual_memory(handle, base_address, size, new_protect, old_protection);
            
            let _r = CloseHandle(handle);

            if ret != 0 {
                return Err(lc!("[x] Error changing section permission."));
            }
        }

        Ok(())
    } 
}

/// Executes any registered TLS Callback function.
///
/// The parameters required are the module's metadata information and a
/// pointer to the base address where the module is mapped in memory.
fn run_tls_callbacks(pe_info: &PeMetadata, image_ptr: *mut c_void) 
{
    unsafe 
    {   
        let entry_point;
        if pe_info.is_32_bit {
            entry_point = image_ptr as isize + pe_info.opt_header_32.address_of_entry_point as isize;
        }
        else {
            entry_point = image_ptr as isize + pe_info.opt_header_64.address_of_entry_point as isize;
        }

        if pe_info.opt_header_64.number_of_rva_and_sizes >= 10
        {
            let address: *mut u8 = (image_ptr as usize + pe_info.opt_header_64.datas_directory[9].virtual_address as usize) as *mut u8;
            let address_of_tls_callback = address.add(24) as *mut usize;
            let mut address_of_tls_callback_array: *mut usize = core::mem::transmute(*address_of_tls_callback);
            
            while *address_of_tls_callback_array != 0
            {
                let tls_callback: extern "system" fn (isize, u32, PVOID) = core::mem::transmute(*address_of_tls_callback_array);
                tls_callback(entry_point, 1, ptr::null_mut());
                address_of_tls_callback_array = address_of_tls_callback_array.add(1);
            }
        }
        
    } 
}