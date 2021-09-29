#[macro_use]
extern crate litcrypt;
use_litcrypt!();


use std::collections::HashMap;
use std::{fs, ptr};
use std::mem::size_of;
use std::ffi::c_void;
use litcrypt::lc;


use bindings::{
    Windows::Win32::System::Diagnostics::Debug::{WriteProcessMemory,IMAGE_OPTIONAL_HEADER32,IMAGE_SECTION_HEADER,
        IMAGE_DATA_DIRECTORY},
    Windows::Win32::System::Memory::{VirtualAlloc,VirtualProtect,VIRTUAL_ALLOCATION_TYPE,PAGE_PROTECTION_FLAGS},
    Windows::Win32::Foundation::HANDLE,
    Windows::Win32::System::Threading::{GetCurrentProcess,NtQueryInformationProcess,PROCESS_BASIC_INFORMATION,PROCESSINFOCLASS},
    Windows::Win32::System::SystemServices::{IMAGE_BASE_RELOCATION,IMAGE_IMPORT_DESCRIPTOR,IMAGE_THUNK_DATA32,IMAGE_THUNK_DATA64},
};


pub const PAGE_READONLY: u32 = 0x2;
pub const PAGE_READWRITE: u32 = 0x4;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE: u32 = 0x10;

pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;

pub const SECTION_MEM_READ: u32 = 0x40000000;
pub const SECTION_MEM_WRITE: u32 = 0x80000000;
pub const SECTION_MEM_EXECUTE: u32 = 0x20000000;

pub fn read_and_map_module (filepath: String) -> Result<i64, String> {

    let file_content = fs::read(filepath).expect(&lc!("[x] Error opening the file."));
    let file_content_ptr = file_content.as_ptr();
    let result = manually_map_module(file_content_ptr)?;

    Ok(result)
}

pub fn manually_map_module (file_ptr: *const u8) -> Result<i64, String> {

    let pe_info = get_pe_metadata(file_ptr)?;
    if (pe_info.is_32_bit && (size_of::<usize>() == 8)) || (!pe_info.is_32_bit && (size_of::<usize>() == 4)) 
    {
        return Err(lc!("[x] The module architecture does not match the process architecture."));
    }

    let dwsize;
    if pe_info.is_32_bit 
    {
        dwsize = pe_info.opt_header_32.SizeOfImage as usize;
    }
    else 
    {
        dwsize = pe_info.opt_header_64.size_of_image as usize;
    }

    unsafe 
    {
        let lpaddress: *mut c_void = std::mem::transmute(487194624 as u64);
        let image_ptr = VirtualAlloc(
            lpaddress,
            dwsize, 
            VIRTUAL_ALLOCATION_TYPE::from(MEM_COMMIT | MEM_RESERVE), 
            PAGE_PROTECTION_FLAGS::from(PAGE_READWRITE)
        );

        map_module_to_memory(file_ptr, image_ptr, &pe_info)?;
        
        relocate_module(&pe_info, image_ptr);

        rewrite_module_iat(&pe_info, image_ptr)?;

        set_module_section_permissions(&pe_info, image_ptr)?;

        Ok(image_ptr as i64)

    }

}

pub fn get_pe_metadata (module_ptr: *const u8) -> Result<PeMetadata,String> {
    
    let mut pe_metadata= PeMetadata::default();

    unsafe {

        let e_lfanew = *((module_ptr as u64 + 0x3C) as *const u32);
        pe_metadata.pe = *((module_ptr as u64 + e_lfanew as u64) as *const u32);

        if pe_metadata.pe != 0x4550 
        {
            return Err(lc!("[x] Invalid PE signature."));
        }

        pe_metadata.image_file_header = *((module_ptr as u64 + e_lfanew as u64 + 0x4) as *mut IMAGE_FILE_HEADER);

        let opt_header: *const u16 = (module_ptr as u64 + e_lfanew as u64 + 0x18) as *const u16; 
        let pe_arch = *(opt_header);

        if pe_arch == 0x010B
        {
            println!("[-] x32 image found.");
            pe_metadata.is_32_bit = true;
            let opt_header_content: *const IMAGE_OPTIONAL_HEADER32 = std::mem::transmute(opt_header);
            pe_metadata.opt_header_32 = *opt_header_content;
        }
        else if pe_arch == 0x020B 
        {
            println!("[-] x64 image found.");
            pe_metadata.is_32_bit = false;
            let opt_header_content: *const IMAGE_OPTIONAL_HEADER64 = std::mem::transmute(opt_header);
            pe_metadata.opt_header_64 = *opt_header_content;
        } 
        else 
        {
            return Err(lc!("[x] Invalid magic value."));
        }

        let mut sections: Vec<IMAGE_SECTION_HEADER> = vec![];

        for i in 0..pe_metadata.image_file_header.number_of_sections
        {
            let section_ptr = (opt_header as u64 + pe_metadata.image_file_header.size_of_optional_header as u64 + (i * 0x28) as u64) as *const u8;
            let section_ptr: *const IMAGE_SECTION_HEADER = std::mem::transmute(section_ptr);
            sections.push(*section_ptr);
        }

        pe_metadata.sections = sections;

        Ok(pe_metadata)
    }
}

pub fn map_module_to_memory(module_ptr: *const u8, image_ptr: *mut c_void, pe_info: &PeMetadata) -> Result<(),String>{

    if (pe_info.is_32_bit && (size_of::<usize>() == 8)) || (!pe_info.is_32_bit && (size_of::<usize>() == 4)) 
    {
        return Err(lc!("[x] The module architecture does not match the process architecture."));
    }

    let nsize;
    if pe_info.is_32_bit 
    {
        nsize = pe_info.opt_header_32.SizeOfHeaders as usize;
    }
    else 
    {
        nsize = pe_info.opt_header_64.size_of_headers as usize;
    }

    unsafe 
    {   

        let hprocess = GetCurrentProcess();
        let lpbaseaddress: *mut c_void = std::mem::transmute(image_ptr);
        let lpbuffer: *const c_void = std::mem::transmute(module_ptr);
        let written: u64 = 0;
        let lpnumberofbyteswritten: *mut usize = std::mem::transmute(&written);
        let write = WriteProcessMemory(
            hprocess, 
            lpbaseaddress, 
            lpbuffer, 
            nsize, 
            lpnumberofbyteswritten
        );

        if !write.as_bool()
        {
            return Err(lc!("[x] Error writing PE headers to the allocated memory."));
        }

        for section in &pe_info.sections
        {
            let section_base_ptr = (image_ptr as u64 + section.VirtualAddress as u64) as *mut u8;
            let section_content_ptr = (module_ptr as u64 + section.PointerToRawData as u64) as *mut u8;          
            let lpbaseaddress: *mut c_void = std::mem::transmute(section_base_ptr);
            let lpbuffer: *const c_void = std::mem::transmute(section_content_ptr);
            let nsize = section.SizeOfRawData as usize;
            let write = WriteProcessMemory(
                hprocess, 
                lpbaseaddress, 
                lpbuffer, 
                nsize, 
                lpnumberofbyteswritten
            );

            if !write.as_bool() || *lpnumberofbyteswritten != nsize
            {
                return Err(lc!("[x] Failed to write PE sections to the allocated memory."))
            }
        }

        Ok(())
    }
}

pub fn relocate_module(pe_info: &PeMetadata, image_ptr: *mut c_void) {

    unsafe {

        let module_memory_base: *mut u64 = std::mem::transmute(image_ptr);
        let image_data_directory;
        let image_delta: i64;
        if pe_info.is_32_bit 
        {
            image_data_directory = pe_info.opt_header_32.DataDirectory[5]; // BaseRelocationTable
            image_delta = module_memory_base as i64 - pe_info.opt_header_32.ImageBase as i64;
        }
        else 
        {
            image_data_directory = pe_info.opt_header_64.datas_directory[5]; // BaseRelocationTable
            image_delta = module_memory_base as i64 - pe_info.opt_header_64.image_base as i64;
        }

        let mut reloc_table_ptr = (module_memory_base as u64 + image_data_directory.VirtualAddress as u64) as *mut i32;
        let mut next_reloc_table_block = -1;

        while next_reloc_table_block != 0 
        {
            let ibr: *mut IMAGE_BASE_RELOCATION = std::mem::transmute(reloc_table_ptr);
            let image_base_relocation = *ibr;
            let reloc_count: i64 = (image_base_relocation.SizeOfBlock as i64 - size_of::<IMAGE_BASE_RELOCATION>() as i64) / 2;

            for i in 0..reloc_count
            {
                let reloc_entry_ptr = (reloc_table_ptr as u64 + size_of::<IMAGE_BASE_RELOCATION>() as u64 + (i * 2) as u64) as *mut u16;
                let reloc_value = *reloc_entry_ptr;

                let reloc_type = reloc_value >> 12;
                let reloc_patch = reloc_value & 0xfff;

                if reloc_type != 0
                {
                    
                    if reloc_type == 0x3
                    {
                        let patch_ptr = (module_memory_base as u64 + image_base_relocation.VirtualAddress as u64 + reloc_patch as u64) as *mut i32;
                        let original_ptr = *patch_ptr;
                        let patch = original_ptr + image_delta as i32;
                        *patch_ptr = patch;
                    }
                    else 
                    {
                        let patch_ptr = (module_memory_base as u64 + image_base_relocation.VirtualAddress as u64 + reloc_patch as u64) as *mut i64;
                        let original_ptr = *patch_ptr;
                        let patch = original_ptr + image_delta as i64;
                        *patch_ptr = patch;
                    }
                }
            }

            reloc_table_ptr = (reloc_table_ptr as u64 + image_base_relocation.SizeOfBlock as u64) as *mut i32;
            next_reloc_table_block = *reloc_table_ptr;

        }


    }
}

pub fn rewrite_module_iat(pe_info: &PeMetadata, image_ptr: *mut c_void) -> Result<(),String> {

    unsafe 
    {
        let module_memory_base: *mut u64 = std::mem::transmute(image_ptr);
        let image_data_directory;
        if pe_info.is_32_bit 
        {
            image_data_directory = pe_info.opt_header_32.DataDirectory[1]; // ImportTable
        }
        else 
        {
            image_data_directory = pe_info.opt_header_64.datas_directory[1]; // ImportTable
        }

        if image_data_directory.VirtualAddress == 0 
        {
            return Ok(()); // No hay import table
        }

        let import_table_ptr = (module_memory_base as u64 + image_data_directory.VirtualAddress as u64) as *mut u64;

        let info = os_info::get();
        let version = info.version().to_string();
        let mut api_set_dict: HashMap<String,String> = HashMap::new();
        if version >= "10".to_string()
        {
            api_set_dict = get_api_mapping();
        }

        let mut counter = 0;
        let mut image_import_descriptor_ptr = (import_table_ptr as u64 + size_of::<IMAGE_IMPORT_DESCRIPTOR>() as u64 * counter) as *mut IMAGE_IMPORT_DESCRIPTOR;
        let mut image_import_descriptor = *image_import_descriptor_ptr;

        while image_import_descriptor.Name != 0
        {
            let mut dll_name = "".to_string();
            let mut c: char = ' ';
            let mut ptr = (module_memory_base as u64 + image_import_descriptor.Name as u64) as *mut u8;
            while c != '\0'
            {
                c = *ptr as char;
                if c != '\0'
                {
                    dll_name.push(c);
                    ptr = ptr.add(1);
                }
            }

            if dll_name == ""
            {
                return Ok(());
            }
            else 
            {
                let lookup_key =  format!("{}{}",&dll_name[..dll_name.len() - 6], ".dll");

                if (version >= 10.to_string() && (dll_name.starts_with("api-") || dll_name.starts_with("ext-"))) &&  api_set_dict.contains_key(&lookup_key)
                {
                    let key = match api_set_dict.get(&lookup_key) {
                        Some(x) => x.to_string(),
                        None => "".to_string(),
                    };

                    if key.len() > 0 
                    {
                        dll_name = key.to_string();
                    }
                }

                let mut module_handle = dinvoke::get_module_base_address(&dll_name) as u64;

                if module_handle == 0
                {
                    module_handle = dinvoke::load_library_a(&dll_name).unwrap() as u64;

                    if module_handle == 0
                    {
                        return Err(lc!("[x] Unable to find the specified module: {}", dll_name)); 
                    }
                }

                if pe_info.is_32_bit
                {
                    let mut i: i64 = 0;

                    loop 
                    {
                        let image_thunk_data = (module_memory_base as u64 + image_import_descriptor.Anonymous.OriginalFirstThunk as u64 
                            + i as u64 * size_of::<u32>() as u64) as *mut IMAGE_THUNK_DATA32;
                        let image_thunk_data = *image_thunk_data;
                        let ft_itd = (module_memory_base as u64 + image_import_descriptor.FirstThunk as u64 +
                            i as u64 * size_of::<u32>() as u64) as *mut i32;
                        if image_thunk_data.u1.AddressOfData == 0
                        {
                            break;
                        }

                        if image_thunk_data.u1.AddressOfData < 0x80000000
                        {
                            let mut imp_by_name_ptr = (module_memory_base as u64 + image_thunk_data.u1.AddressOfData as u64 + 
                                size_of::<u16>() as u64) as *mut u8;
                            let mut import_name: String = "".to_string();
                            let mut c: char = ' ';
                            while c != '\0'
                            {
                                c = *imp_by_name_ptr as char;
                                if c != '\0'
                                {
                                    import_name.push(c);
                                }

                                imp_by_name_ptr = imp_by_name_ptr.add(1);
                            }

                            let func_ptr = dinvoke::get_function_address(module_handle as i64, import_name);
                            *ft_itd = func_ptr as i32;

                        }
                        else 
                        {
                            let f_ordinal = (image_thunk_data.u1.AddressOfData & 0xFFFF) as u32;
                            let func_ptr = dinvoke::get_function_address_ordinal(module_handle as i64, f_ordinal);
                            let func_ptr = func_ptr as *mut i32;
                            *ft_itd = func_ptr as i32;
                        }

                        i = i + 1;
                    }
                }
                else 
                {
                    let mut i: i64 = 0;

                    loop 
                    {
                        let image_thunk_data = (module_memory_base as u64 + image_import_descriptor.Anonymous.OriginalFirstThunk as u64 
                            + i as u64 * size_of::<u64>() as u64) as *mut IMAGE_THUNK_DATA64;
                        let image_thunk_data = *image_thunk_data;
                        let ft_itd = (module_memory_base as u64 + image_import_descriptor.FirstThunk as u64 +
                            i as u64 * size_of::<u64>() as u64) as *mut i64;
                        

                        if image_thunk_data.u1.AddressOfData == 0
                        {
                            break;
                        }

                        if image_thunk_data.u1.AddressOfData < 0x8000000000000000
                        {
                            let mut imp_by_name_ptr = (module_memory_base as u64 + image_thunk_data.u1.AddressOfData as u64 + 
                                size_of::<u16>() as u64) as *mut u8;
                            let mut import_name: String = "".to_string();
                            let mut c: char = ' ';
                            while c != '\0'
                            {
                                c = *imp_by_name_ptr as char;
                                if c != '\0'
                                {
                                    import_name.push(c);
                                }

                                imp_by_name_ptr = imp_by_name_ptr.add(1);
                            }

                            let func_ptr = dinvoke::get_function_address(module_handle as i64, import_name) as *mut i64;
                            *ft_itd = func_ptr as i64;
                        }
                        else 
                        {
     
                            let f_ordinal = (image_thunk_data.u1.AddressOfData & 0xFFFF) as u32;
                            let func_ptr = dinvoke::get_function_address_ordinal(module_handle as i64, f_ordinal);
                            *ft_itd = func_ptr as i64;
                        }

                        i = i + 1;
                    }
                }
  
            }

            counter = counter + 1;
            image_import_descriptor_ptr = (import_table_ptr as u64 + size_of::<IMAGE_IMPORT_DESCRIPTOR>() as u64 * counter) as *mut IMAGE_IMPORT_DESCRIPTOR;
            image_import_descriptor = *image_import_descriptor_ptr;

        }

        Ok(())
    }
}

fn get_api_mapping() -> HashMap<String,String> {

    unsafe 
    {
        let mut processhandle = HANDLE::default();
        processhandle.0 = -1; 
        let processinformation: *mut c_void = std::mem::transmute(&PROCESS_BASIC_INFORMATION::default());
        let _err = NtQueryInformationProcess(
            processhandle, 
            PROCESSINFOCLASS::from(0), 
            processinformation, 
            size_of::<PROCESS_BASIC_INFORMATION>() as u32, 
            ptr::null_mut()
        );

        let process_information_ptr: *mut PROCESS_BASIC_INFORMATION = std::mem::transmute(processinformation);

        let api_set_map_offset:u64;

        if size_of::<usize>() == 4
        {
            api_set_map_offset = 0x38;
        }
        else 
        {
            api_set_map_offset = 0x68;
        }

        let mut api_set_dict: HashMap<String,String> = HashMap::new();

        let api_set_namespace_ptr = *(((*process_information_ptr).PebBaseAddress as u64 + api_set_map_offset) as *mut isize);
        let api_set_namespace_ptr: *mut ApiSetNamespace = std::mem::transmute(api_set_namespace_ptr);
        let namespace = *api_set_namespace_ptr; 

        for i in 0..namespace.count
        {

            let set_entry_ptr = (api_set_namespace_ptr as u64 + namespace.entry_offset as u64 + (i * size_of::<ApiSetNamespaceEntry>() as i32) as u64) as *mut ApiSetNamespaceEntry;
            let set_entry = *set_entry_ptr;

            let mut api_set_entry_name_ptr = (api_set_namespace_ptr as u64 + set_entry.name_offset as u64) as *mut u8;
            let mut api_set_entry_name: String = "".to_string();
            let mut j = 0;
            while j < (set_entry.name_length / 2 )
            {
                let c = *api_set_entry_name_ptr as char;
                if c != '\0' // Esto se podria meter en una funcion aparte
                {
                    api_set_entry_name.push(c);
                    j = j + 1;
                } 

                api_set_entry_name_ptr = api_set_entry_name_ptr.add(1); 

            }

            let api_set_entry_key = format!("{}{}",&api_set_entry_name[..api_set_entry_name.len()-2], ".dll");
            let mut set_value_ptr: *mut ApiSetValueEntry = ptr::null_mut();

            if set_entry.value_length == 1
            {
                let value = (api_set_namespace_ptr as u64 + set_entry.value_offset as u64) as *mut u8;
                set_value_ptr = std::mem::transmute(value);
            }
            else if set_entry.value_length > 1
            {
                for x in 0..set_entry.value_length 
                {
                    let host_ptr = (api_set_entry_name_ptr as u64 + set_entry.value_offset as u64 + size_of::<ApiSetValueEntry>() as u64 * x as u64) as *mut u8;
                    let mut c: u8 = u8::default();
                    let mut host: String = "".to_string();
                    while c as char != '\0'
                    {
                        c = *host_ptr;
                        if c as char != '\0'
                        {
                            host.push(c as char);
                        }
                    }

                    if host != api_set_entry_name
                    {
                        set_value_ptr = (api_set_namespace_ptr as u64 + set_entry.value_offset as u64 + size_of::<ApiSetValueEntry>() as u64 * x as u64) as *mut ApiSetValueEntry;
                    }
                }

                if set_value_ptr == ptr::null_mut()
                {
                    set_value_ptr = (api_set_namespace_ptr as u64 + set_entry.value_offset as u64) as *mut ApiSetValueEntry;
                }
            }

            let set_value = *set_value_ptr;
            let mut api_set_value: String = "".to_string();
            if set_value.value_count != 0
            {
                let mut value_ptr = (api_set_namespace_ptr as u64 + set_value.value_offset as u64) as *mut u8;
                let mut r = 0;
                while r < (set_value.value_count / 2 )
                {
                    let c = *value_ptr as char;
                    if c != '\0' 
                    {
                        api_set_value.push(c);
                        r = r + 1;
                    } 
    
                    value_ptr = value_ptr.add(1); 
    
                }
            }

            api_set_dict.insert(api_set_entry_key, api_set_value);

        }

        api_set_dict

    }
}

pub fn set_module_section_permissions(pe_info: &PeMetadata, image_ptr: *mut c_void) -> Result<(),String> {

    unsafe 
    {
        let base_of_code;

        if pe_info.is_32_bit
        {
            base_of_code = pe_info.opt_header_32.BaseOfCode as usize;
        }
        else 
        {
            base_of_code = pe_info.opt_header_64.base_of_code as usize;
        }

        let mut flnewprotect = PAGE_PROTECTION_FLAGS::default();
        flnewprotect.0 = PAGE_READONLY;
        let lpfloldprotect: *mut PAGE_PROTECTION_FLAGS = std::mem::transmute(&PAGE_PROTECTION_FLAGS::default());
        VirtualProtect(
            image_ptr, 
            base_of_code, 
            flnewprotect, 
            lpfloldprotect
        );

        for section in &pe_info.sections
        {
            let is_read = (section.Characteristics.0 & SECTION_MEM_READ) != 0;
            let is_write = (section.Characteristics.0 & SECTION_MEM_WRITE) != 0;
            let is_execute = (section.Characteristics.0 & SECTION_MEM_EXECUTE) != 0;
            let new_protect: u32;

            if is_read & !is_write & !is_execute
            {
                new_protect = PAGE_READONLY;
            }
            else if is_read & is_write & !is_execute
            {
                new_protect = PAGE_READWRITE;
            } 
            else if is_read & is_write & is_execute
            {
                new_protect = PAGE_EXECUTE_READWRITE;
            }
            else if is_read & !is_write & is_execute
            {
                new_protect = PAGE_EXECUTE_READ;
            }
            else if !is_read & !is_write & is_execute
            {
                new_protect = PAGE_EXECUTE;
            }
            else
            {
                return Err(lc!("[x] Unknown section permission."));
            }

            let lpaddress: *mut c_void = (image_ptr as u64 + section.VirtualAddress as u64) as *mut c_void;
            let dwsize = section.Misc.VirtualSize as usize;
            let mut flnewprotect = PAGE_PROTECTION_FLAGS::default();
            flnewprotect.0 = new_protect;
            let lpfloldprotect: *mut PAGE_PROTECTION_FLAGS = std::mem::transmute(&PAGE_PROTECTION_FLAGS::default());
            VirtualProtect(
                lpaddress, 
                dwsize, 
                flnewprotect, 
                lpfloldprotect
            );
        }

        Ok(())
    } 
}

#[derive(Clone)]
#[repr(C)]
pub struct PeMetadata {
    pe: u32,
    is_32_bit: bool,
    image_file_header: IMAGE_FILE_HEADER,
    opt_header_32: IMAGE_OPTIONAL_HEADER32,
    opt_header_64: IMAGE_OPTIONAL_HEADER64,
    sections: Vec<IMAGE_SECTION_HEADER> 
}

impl Default for PeMetadata {
    fn default() -> PeMetadata {
        PeMetadata {
            pe: u32::default(),
            is_32_bit: false,
            image_file_header: IMAGE_FILE_HEADER::default(),
            opt_header_32: IMAGE_OPTIONAL_HEADER32::default(),
            opt_header_64: IMAGE_OPTIONAL_HEADER64::default(),
            sections: Vec::default(),  
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default, PartialEq, Debug, Eq)]
struct ApiSetNamespace {
    unused: [u8;12],
    count: i32, // offset 0x0C
    entry_offset: i32, // offset 0x10
}

#[repr(C)]
#[derive(Copy, Clone, Default, PartialEq, Debug, Eq)]
struct ApiSetNamespaceEntry {
    unused1: [u8;4],
    name_offset: i32, // offset 0x04
    name_length: i32, // offset 0x08
    unused2: [u8;4],
    value_offset: i32, // offset 0x10
    value_length: i32, // offset 0x14
}

#[repr(C)]
#[derive(Copy, Clone, Default, PartialEq, Debug, Eq)]
struct ApiSetValueEntry {
    flags: i32, // offset 0x00
    name_offset: i32, // offset 0x04
    name_count: i32, // offset 0x08
    value_offset: i32, // offset 0x0C
    value_count: i32, // offset 0x10
}

#[derive(Copy, Clone, Default, PartialEq, Debug, Eq)]
#[repr(C)]
struct IMAGE_FILE_HEADER {
    machine: u16,
    number_of_sections: u16,
    time_data_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[derive(Copy, Clone,Default)]
#[repr(C)] // required to keep fields order, otherwise Rust may change that order randomly
struct IMAGE_OPTIONAL_HEADER64 {
        magic: u16, 
        major_linker_version: u8, 
        minor_linker_version: u8, 
        size_of_code: u32, 
        size_of_initialized_data: u32, 
        size_of_unitialized_data: u32, 
        address_of_entry_point: u32, 
        base_of_code: u32, 
        image_base: u64, 
        section_alignment: u32, 
        file_alignment: u32, 
        major_operating_system_version: u16, 
        minor_operating_system_version: u16, 
        major_image_version: u16,
        minor_image_version: u16, 
        major_subsystem_version: u16,
        minor_subsystem_version: u16, 
        win32_version_value: u32, 
        size_of_image: u32, 
        size_of_headers: u32, 
        checksum: u32, 
        subsystem: u16, 
        dll_characteristics: u16, 
        size_of_stack_reserve: u64, 
        size_of_stack_commit: u64, 
        size_of_heap_reserve: u64, 
        size_of_heap_commit: u64, 
        loader_flags: u32, 
        number_of_rva_and_sizes: u32, 
        datas_directory: [IMAGE_DATA_DIRECTORY; 16], 
}