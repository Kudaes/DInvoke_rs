#![no_std]
#![no_main]


#[macro_use]
extern crate litcrypt2;
use_litcrypt!();

extern crate alloc;


use alloc::ffi::CString;
use alloc::vec::Vec;
use alloc::string::{String, ToString};
use alloc::collections::BTreeMap;
use data::{EAT, ApiSetNamespace, ApiSetNamespaceEntry, ApiSetValueEntry, CloseHandle, EnumProcessModules, GetCurrentProcess, GetModuleBaseNameW, GetModuleFileNameExW, LoadLibraryA, NtQueryInformationProcess, ProcessBasicInformation, WindowsHeapAllocator, HANDLE, MAX_PATH, OSVERSIONINFOW, PVOID};
use core::cell::UnsafeCell;
use core::char::decode_utf16;
use core::fmt::Write;
use core::ptr::{self};
use core::ffi::c_void;
use core::str;


#[global_allocator]
static GLOBAL: WindowsHeapAllocator = WindowsHeapAllocator;

extern "C" {
    fn run_indirect_syscall(structure: PVOID) -> *mut u8;
    fn restore();
}

#[repr(C)] 
struct Configuration
{
    jump_address: usize,
    return_address: usize,
    nargs: usize,
    arg01: usize,
    arg02: usize,
    arg03: usize,
    arg04: usize,
    arg05: usize,
    arg06: usize,
    arg07: usize,
    arg08: usize,
    arg09: usize,
    arg10: usize,
    arg11: usize,
    syscall_id: u32
}

/// Retrieves the base address of a module loaded in the current process.
///
/// In case that the module can't be found in the current process, it will
/// return 0.
///
/// # Examples
///
/// ```
/// let ntdll = dinvoke::get_module_base_address("ntdll.dll");
///
/// if ntdll != 0 {
///     utils::println!("The base address of ntdll.dll is 0x{:X}.", ntdll);
/// }
pub fn get_module_base_address (module_name: &str) -> usize
{
    let modules = match get_modules_list() {
        Ok(val) => val,
        Err(_x) => {
            return 0;
        }
    };

    for m in modules 
    {
        let name = match get_module_name(m) {
            Ok(val) => val,
            Err(_x) => {
                continue;
            }
        };

        let path = match get_module_path(m) {
            Ok(val) => val,
            Err(_x) => {
                continue;
            }
        };

        if name.to_ascii_lowercase() == module_name.to_ascii_lowercase() ||
            path.to_ascii_lowercase() == module_name.to_ascii_lowercase()
        {
            return m;
        }
    }

    0
}

fn get_modules_list() -> Result<Vec<usize>, u32> 
{

    let mut mod_handles: Vec<usize> = Vec::new();
    let mut reserved = 0;
    let mut needed = 0;

    // Code extracted from winproc
    let enum_mods = |mod_handles: &mut Vec<usize>, needed: *mut u32| {
        let current_process = HANDLE{ id: -1 };
        let cb = mod_handles.len() as u32;

        let res = unsafe { EnumProcessModules(current_process, mod_handles.as_mut_ptr() as _, cb, needed) };

        if res == 0 {
            Err(-1i32 as u32)
        } else {
            Ok(())
        }
    };

    // Code extracted from winproc
    loop {
        enum_mods(&mut mod_handles, &mut needed)?;
        if needed <= reserved {
            break;
        }
        reserved = needed;
        mod_handles.resize(needed as usize, 0);
    }
    

    Ok(mod_handles)
    
}

fn from_wide_lossy(buffer: &[u16]) -> String {
    decode_utf16(buffer.iter().cloned())
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

fn get_module_name(hmodule: usize) -> Result<String,u32>
{
    unsafe 
    {
        let current_process = HANDLE{ id: -1};
        let mut buffer: [u16; MAX_PATH as _] = core::mem::zeroed();

        let res = GetModuleBaseNameW(current_process, hmodule as _, buffer.as_mut_ptr(), MAX_PATH);
        if res == 0 {
            Err(-1i32 as u32)
        } else {
            Ok(from_wide_lossy(&buffer[0..res as usize]))
        }
    }
}

fn get_module_path(hmodule: usize) -> Result<String,u32>
{
    unsafe 
    {
        let current_process = HANDLE{ id: -1};
        let mut buffer: [u16; MAX_PATH as _] = core::mem::zeroed();

        let res = GetModuleFileNameExW(current_process, hmodule as _, buffer.as_mut_ptr(), MAX_PATH);
        if res == 0 {
            Err(-1i32 as u32)
        } else {
            Ok(from_wide_lossy(&buffer[0..res as usize]))
        }
    }
}

/// Retrieves the address of an exported function from the specified module.
///
/// This functions is analogous to GetProcAddress from Win32. The exported 
/// function's address is obtained by walking and parsing the EAT of the  
/// specified module.
///
/// In case that the function's address can't be retrieved, it will return 0.
///
/// # Examples
///
/// ```
/// let ntdll = dinvoke::get_module_base_address("ntdll.dll");
///
/// if ntdll != 0
/// {
///     let addr = dinvoke::get_function_address(ntdll, "NtCreateThread");    
///     utils::println!("The address where NtCreateThread is located at is 0x{:X}.", addr);
/// }
/// ```
pub fn get_function_address(module_base_address: usize, function: &str) -> usize {

    unsafe
    {
        let mut function_ptr: *mut i32 = ptr::null_mut();
        let pe_header = *((module_base_address + 0x3C) as *mut i32);
        let opt_header: usize = module_base_address + (pe_header as usize) + 0x18;
        let magic = *(opt_header as *mut i16);
        let p_export: usize;

        if magic == 0x010b  {
            p_export = opt_header + 0x60;
        } else {
            p_export = opt_header + 0x70;
        }

        let export_rva = *(p_export as *mut i32);
        let ordinal_base = *((module_base_address + export_rva as usize + 0x10) as *mut i32);
        let number_of_names = *((module_base_address + export_rva as usize + 0x18) as *mut i32);
        let functions_rva = *((module_base_address + export_rva as usize + 0x1C) as *mut i32);
        let names_rva = *((module_base_address + export_rva as usize + 0x20) as *mut i32);
        let ordinals_rva = *((module_base_address + export_rva as usize + 0x24) as *mut i32);

        for x in 0..number_of_names 
        {

            let address = *((module_base_address + names_rva as usize + x as usize * 4) as *mut i32);
            let mut function_name_ptr = (module_base_address + address as usize) as *mut u8;
            let mut function_name: String = String::new();

            while *function_name_ptr as char != '\0' 
            { 
                function_name.push(*function_name_ptr as char);
                function_name_ptr = function_name_ptr.add(1);
            }

            if function_name.to_lowercase() == function.to_lowercase() 
            {
                let function_ordinal = *((module_base_address + ordinals_rva as usize + x as usize * 2) as *mut i16) as i32 + ordinal_base;
                let function_rva = *(((module_base_address + functions_rva as usize + (4 * (function_ordinal - ordinal_base)) as usize )) as *mut i32);
                function_ptr = (module_base_address + function_rva as usize) as *mut i32;

                function_ptr = get_forward_address(function_ptr as *mut u8) as *mut i32;
                
                break;
            }

        }

        let mut ret: usize = 0;

        if function_ptr != ptr::null_mut() {
            ret = function_ptr as usize;
        }
    
        ret

    }
}

fn get_forward_address(function_ptr: *mut u8) -> usize {
   
    unsafe 
    {
        let mut c = 100;
        let mut ptr = function_ptr.clone();
        let mut forwarded_names = String::new();

        loop 
        {
            if *ptr as char != '\0'{
                forwarded_names.push(*ptr as char);
            } else {
                break;    
            }

            ptr = ptr.add(1);
            c = c - 1;

            // Assume there wont be an exported address with len > 100
            if c == 0 {
                return function_ptr as usize;
            }

        }

        let values: Vec<&str> = forwarded_names.split(".").collect();
        if values.len() != 2 {
            return function_ptr as usize;
        }

        let mut forwarded_module_name = String::from(values[0]);
        let forwarded_export_name = String::from(values[1]);

        if forwarded_module_name.len() < 2 || forwarded_export_name.len() == 0 {
            return function_ptr as usize;
        }

        let api_set = get_api_mapping();

        let mut lookup_key = String::new();
        let _ = write!(lookup_key, "{}.dll",&forwarded_module_name[..forwarded_module_name.len() - 2]);

        if api_set.contains_key(&lookup_key)
        {
            forwarded_module_name = match api_set.get(&lookup_key) {
                Some(x) => String::from(x),
                None => {forwarded_module_name}
            };
        }
        else {
            forwarded_module_name = forwarded_module_name + ".dll";
        }

        let mut module = get_module_base_address(&forwarded_module_name);

        // If the module is not already loaded, we try to load it calling LoadLibraryA
        if module == 0 {
            module = load_library_a(&forwarded_module_name);
        }

        if module != 0 {
            return get_function_address(module, &forwarded_export_name);
        }

        function_ptr as usize
    }
}

pub fn get_api_mapping() -> BTreeMap<String,String> {

    unsafe 
    {
        let handle = GetCurrentProcess();
        let p = ProcessBasicInformation::default();
        let process_information: *mut c_void = core::mem::transmute(&p);
        let _ret = nt_query_information_process(
            handle, 
            0, 
            process_information,  
            size_of::<ProcessBasicInformation>() as u32, 
            ptr::null_mut());
        
        let _r = CloseHandle(handle);

        let process_information_ptr: *mut ProcessBasicInformation = core::mem::transmute(process_information);

        let api_set_map_offset: usize;

        if size_of::<usize>() == 4 {
            api_set_map_offset = 0x38;
        } else {
            api_set_map_offset = 0x68;
        }

        let mut api_set_dict: BTreeMap<String,String> = BTreeMap::new();

        let api_set_namespace_ptr = *(((*process_information_ptr).peb_base_address as usize + api_set_map_offset) as *mut usize);
        let api_set_namespace_ptr: *mut ApiSetNamespace = core::mem::transmute(api_set_namespace_ptr);
        let namespace = *api_set_namespace_ptr; 

        for i in 0..namespace.count
        {

            let set_entry_ptr = (api_set_namespace_ptr as usize + namespace.entry_offset as usize + (i * size_of::<ApiSetNamespaceEntry>() as i32) as usize) as *mut ApiSetNamespaceEntry;
            let set_entry = *set_entry_ptr;

            let mut api_set_entry_name_ptr = (api_set_namespace_ptr as usize + set_entry.name_offset as usize) as *mut u8;
            let mut api_set_entry_name: String = String::new();
            let mut j = 0;
            while j < (set_entry.name_length / 2 )
            {
                let c = *api_set_entry_name_ptr as char;
                if c != '\0'
                {
                    api_set_entry_name.push(c);
                    j = j + 1;
                } 

                api_set_entry_name_ptr = api_set_entry_name_ptr.add(1); 

            }

            let mut api_set_entry_key = String::new();
            let _ = write!(api_set_entry_key, "{}.dll",&api_set_entry_name[..api_set_entry_name.len()-2]);
            let mut set_value_ptr: *mut ApiSetValueEntry = ptr::null_mut();

            if set_entry.value_length == 1
            {
                let value = (api_set_namespace_ptr as usize + set_entry.value_offset as usize) as *mut u8;
                set_value_ptr = core::mem::transmute(value);
            }
            else if set_entry.value_length > 1
            {
                for x in 0..set_entry.value_length 
                {
                    let host_ptr = (api_set_entry_name_ptr as usize + set_entry.value_offset as usize + size_of::<ApiSetValueEntry>() as usize * x as usize) as *mut u8;
                    let mut c: u8 = u8::default();
                    let mut host: String = String::new();
                    while c as char != '\0'
                    {
                        c = *host_ptr;
                        if c as char != '\0' {
                            host.push(c as char);
                        }
                    }

                    if host != api_set_entry_name {
                        set_value_ptr = (api_set_namespace_ptr as usize + set_entry.value_offset as usize + size_of::<ApiSetValueEntry>() as usize * x as usize) as *mut ApiSetValueEntry;
                    }
                }

                if set_value_ptr == ptr::null_mut() {
                    set_value_ptr = (api_set_namespace_ptr as usize + set_entry.value_offset as usize) as *mut ApiSetValueEntry;
                }
            }

            let set_value = *set_value_ptr;
            let mut api_set_value: String = String::new();
            if set_value.value_count != 0
            {
                let mut value_ptr = (api_set_namespace_ptr as usize + set_value.value_offset as usize) as *mut u8;
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

/// Dynamically calls LoadLibraryA.
///
/// It will return either the module's base address or 0.
///
/// # Examples
///
/// ```
/// let ret = dinvoke::load_library_a("ntdll.dll");
///
/// if ret != 0 { utils::println!("ntdll.dll base address is 0x{:X}.", addr) };
/// ```
pub fn load_library_a(module: &str) -> usize {

    unsafe 
    {   
        let ret: Option<usize>;
        let func_ptr: LoadLibraryA;
        let name = CString::new(String::from(module)).expect("");
        let module_name: *mut u8 = core::mem::transmute(name.as_ptr());
        let k32 = get_module_base_address(&lc!("kernel32.dll")); 
        dynamic_invoke!(k32,&lc!("LoadLibraryA"),func_ptr,ret,module_name);

        match ret
        {
            Some(x) => { return x; },
            None => { return 0; }
        }
    }     
}

/// Dynamically calls NtQueryInformationProcess.
///
/// It returns the NTSTATUS value.
pub fn nt_query_information_process (handle: HANDLE, process_information_class: u32, process_information: *mut c_void, length: u32, return_length: *mut u32) -> i32 {
    
    unsafe 
    {
        let ret;
        let func_ptr: NtQueryInformationProcess;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("NtQueryInformationProcess"),func_ptr,ret,handle,process_information_class,process_information,length,return_length);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    } 
}

// Dynamically calls NtAllocateVirtualMemory.
///
/// It returns the NTSTATUS value.
pub fn nt_allocate_virtual_memory (handle: HANDLE, base_address: *mut PVOID, zero_bits: usize, size: *mut usize, allocation_type: u32, protection: u32) -> i32 {

    unsafe 
    {
        let ret;
        let func_ptr: data::NtAllocateVirtualMemory;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        
        dynamic_invoke!(ntdll,&lc!("NtAllocateVirtualMemory"),func_ptr,ret,handle,base_address,zero_bits,size,allocation_type,protection);
        match ret {
            Some(x) => return x,
            None => return -1,
        }
    }   
}

/// Dynamically calls NtWriteVirtualMemory.
///
/// It returns the NTSTATUS value.
pub fn nt_write_virtual_memory (handle: HANDLE, base_address: PVOID, buffer: PVOID, size: usize, bytes_written: *mut usize) -> i32 {

    unsafe 
    {
        let ret;
        let func_ptr: data::NtWriteVirtualMemory;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));

        dynamic_invoke!(ntdll,&lc!("NtWriteVirtualMemory"),func_ptr,ret,handle,base_address,buffer,size,bytes_written);
        match ret {
            Some(x) => return x,
            None => return -1,
        }
    }

}

/// Dynamically calls NtProtectVirtualMemory.
///
/// It returns the NTSTATUS value.
pub fn nt_protect_virtual_memory (handle: HANDLE, base_address: *mut PVOID, size: *mut usize, new_protection: u32, old_protection: *mut u32) -> i32 {
    
    unsafe 
    {
        let ret;
        let func_ptr: data::NtProtectVirtualMemory;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));

        dynamic_invoke!(ntdll,&lc!("NtProtectVirtualMemory"),func_ptr,ret,handle,base_address,size,new_protection,old_protection);
        match ret {
            Some(x) => return x,
            None => return -1,
        }
    } 
}

/// Dynamically calls NtProtectVirtualMemory.
///
/// It returns the NTSTATUS value.
pub fn rtl_get_version(version_information: *mut OSVERSIONINFOW) -> i32 {
    
    unsafe 
    {
        let ret;
        let func_ptr: data::RtlGetVersion;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));

        dynamic_invoke!(ntdll,&lc!("RtlGetVersion"),func_ptr,ret,version_information);
        match ret {
            Some(x) => return x,
            None => return -1,
        }
    } 
}

/// Retrieves the address of an exported function from the specified module by its ordinal.
///
/// In case that the function's address can't be retrieved, it will return 0.
///
/// This functions internally calls LdrGetProcedureAddress.
///
/// # Examples
///
/// ```
/// let ntdll = dinvoke::get_module_base_address("ntdll.dll");
///
/// if ntdll != 0
/// {
///     let ordinal: u32 = 8; 
///     let addr = dinvoke::get_function_address_ordinal(ntdll, ordinal);
///     if addr != 0 { 
///         utils::println!("The function with ordinal 8 is located at 0x{:X}.", addr);
///     }
/// }
/// ```
pub fn get_function_address_by_ordinal(module_base_address: usize, ordinal: u32) -> usize 
{
    let ret = ldr_get_procedure_address(module_base_address, "", ordinal);
    ret    
}

/// Retrieves the address of an exported function from the specified module either by its name 
/// or by its ordinal number.
///
/// This functions internally calls LdrGetProcedureAddress.
///
/// In case that the function's address can't be retrieved, it will return 0.
///
/// # Examples
///
/// ```
/// let ntdll = dinvoke::get_module_base_address("ntdll.dll");
///
/// if ntdll != 0
/// {
///     let ordinal: u32 = 8; // Ordinal 8 represents the function RtlDispatchAPC
///     let addr = dinvoke::ldr_get_procedure_address(ntdll,"", 8);
///     if addr != 0 {
///         utils::println!("The function with ordinal 8 is located at 0x{:X}.", addr);
///     }
/// }
/// ```
pub fn ldr_get_procedure_address (module_handle: usize, function_name: &str, ordinal: u32) -> usize {

    unsafe 
    {   
        let ret: Option<i32>;
        let func_ptr: data::LdrGetProcedureAddress;
        let hmodule: PVOID = module_handle as _;
        let r = usize::default();
        let return_address: *mut c_void = core::mem::transmute(&r);
        let return_address: *mut PVOID = core::mem::transmute(&return_address);
        let f: UnsafeCell<String> = String::default().into();
        let mut fun_name: *mut String = core::mem::transmute(f.get());

        if function_name == "" {
            fun_name = ptr::null_mut();
        }
        else {
            *fun_name = function_name.to_string();
        }

        let module_base_address = get_module_base_address(&lc!("ntdll.dll")); 
        dynamic_invoke!(module_base_address,&lc!("LdrGetProcedureAddress"),func_ptr,ret,hmodule,fun_name,ordinal,return_address);

        match ret {
            Some(x) => 
            {
                if x == 0 {
                    return *return_address as usize;
                } 
                else {
                    return 0;
                }
            },
            None => return 0,
        }
    }
}


/// Dynamically calls an exported function from the specified module.
///
/// This macro will use the dinvoke crate functions to obtain an exported
/// function address of the specified module at runtime by walking process structures 
/// and PE headers.
///
/// it returns the same data type that the called function would return
/// using the 4th argument passed to the macro.
/// 
/// # Example - Dynamically calling LoadLibraryA
///
/// ```ignore
/// let kernel32 = manualmap::read_and_map_module(r"c:\windows\system32\kernel32.dll", false, false).unwrap();
/// let mut ret:Option<HINSTANCE>;
/// let function_ptr: data::LoadLibraryA;
/// let name = CString::new("ntdll.dll").expect("CString::new failed");
/// //dinvoke::dynamic_invoke(usize,&str,<function_type>,Option<return_type>,[arguments])
/// dinvoke::dynamic_invoke(kernel32.1, "LoadLibraryA", function_ptr, ret, name.as_ptr() as *mut u8);
///
/// match ret {
///     Some(x) => {println!("ntdll base address is 0x{:X}",x.0);},
///     None => println!("Error calling LoadLibraryA"),
/// }
/// ```
#[macro_export]
macro_rules! dynamic_invoke {
    ($a:expr, $b:expr, $c:expr, $d:expr, $($e:tt)*) => {

        let function_ptr = $crate::get_function_address($a, $b);
        if function_ptr != 0
        {
            $c = core::mem::transmute(function_ptr);
            $d = Some($c($($e)*));
        }
        else {
            $d = None;
        }

    };
}

#[macro_export]
macro_rules! indirect_syscall {

    ($a:expr, $($x:expr),*) => {
        
        unsafe
        {
            let mut temp_vec = alloc::vec::Vec::new();
            let t = $crate::prepare_syscall($a);
            let r = -1isize;
            let mut res: *mut u8 = core::mem::transmute(r);
            if t.0 != u32::MAX 
            {
                temp_vec.push(t.1);
                $(
                    let temp = $x as usize; // This is meant to convert integers with smaller size than 8 bytes
                    temp_vec.push(temp);
                )*
                
                res = $crate::run_syscall(temp_vec, t.0);
            }

            res
        }
    };
}

pub fn get_ntdll_eat(module_base_address: usize) -> EAT {

    unsafe
    {
        let mut eat: EAT = EAT::default();

        let mut function_ptr:*mut i32;
        let pe_header = *((module_base_address + 0x3C) as *mut i32);
        let opt_header: usize = module_base_address + (pe_header as usize) + 0x18;
        let magic = *(opt_header as *mut i16);
        let p_export: usize;

        if magic == 0x010b  {
            p_export = opt_header + 0x60;
        } else {
            p_export = opt_header + 0x70;
        }

        let export_rva = *(p_export as *mut i32);
        let ordinal_base = *((module_base_address + export_rva as usize + 0x10) as *mut i32);
        let number_of_names = *((module_base_address + export_rva as usize + 0x18) as *mut i32);
        let functions_rva = *((module_base_address + export_rva as usize + 0x1C) as *mut i32);
        let names_rva = *((module_base_address + export_rva as usize + 0x20) as *mut i32);
        let ordinals_rva = *((module_base_address + export_rva as usize + 0x24) as *mut i32);

        for x in 0..number_of_names 
        {

            let address = *((module_base_address + names_rva as usize + x as usize * 4) as *mut i32);
            let mut function_name_ptr = (module_base_address + address as usize) as *mut u8;
            let mut function_name: String = String::new();

            while *function_name_ptr as char != '\0' // null byte
            { 
                function_name.push(*function_name_ptr as char);
                function_name_ptr = function_name_ptr.add(1);
            }

            if function_name.starts_with("Zw")
            {
                let function_ordinal = *((module_base_address + ordinals_rva as usize + x as usize * 2) as *mut i16) as i32 + ordinal_base;
                let function_rva = *(((module_base_address + functions_rva as usize + (4 * (function_ordinal - ordinal_base)) as usize )) as *mut i32);
                function_ptr = (module_base_address + function_rva as usize) as *mut i32;

                function_name = function_name.replace("Zw", "Nt");
                eat.insert(function_ptr as usize,function_name );
            }
        }
        eat
    }
}

pub fn get_syscall_id(eat: &EAT, function_name: &str) -> u32 {
    let mut i = 0;
    for (_a,b) in eat.iter()
    {
        if b == function_name {
            return i;
        }

        i = i + 1;
    }

    u32::MAX
}

pub fn find_syscall_address(address: usize) -> usize
{
    unsafe
    {
        let stub: [u8;2] = [ 0x0F, 0x05 ];
        let mut ptr:*mut u8 = address as *mut u8;
        for _i in 0..23
        {
            if *(ptr.add(1)) == stub[0] && *(ptr.add(2)) == stub[1] {
                return ptr.add(1) as usize;
            }

            ptr = ptr.add(1);
        }
    }

    0usize
}

pub fn prepare_syscall(function_name: &str) -> (u32, usize)
{

    let ntdll = get_module_base_address(&lc!("ntdll.dll"));
    let eat = get_ntdll_eat(ntdll);
    let id = get_syscall_id(&eat, function_name);
    if id != u32::MAX
    {
        let function_addr = get_function_address(ntdll, function_name);
        let syscall_addr: usize = find_syscall_address(function_addr as usize);
        if syscall_addr != 0 {
            return (id as u32,syscall_addr);
        }
    }
    
    (u32::MAX,0)
}

pub fn run_syscall(mut args: Vec<usize>, id: u32) -> *mut u8
{
    use data::PVOID;

    unsafe 
    {
        let mut config: Configuration = core::mem::zeroed();
        config.jump_address = args.remove(0);
        let restore_address = (restore as *const()) as usize;
        config.return_address = restore_address;
        config.syscall_id = id;

        let mut args_number = args.len();
        config.nargs = args_number;

        while args_number > 0
        {
            match args_number
            {
                11  => config.arg11 = args[args_number-1],
                10  => config.arg10 = args[args_number-1],
                9   => config.arg09 = args[args_number-1],
                8   => config.arg08 = args[args_number-1],
                7   => config.arg07 = args[args_number-1],
                6   => config.arg06 = args[args_number-1],
                5   => config.arg05 = args[args_number-1],
                4   => config.arg04 = args[args_number-1],
                3   => config.arg03 = args[args_number-1],
                2   => config.arg02 = args[args_number-1],
                1   => config.arg01 = args[args_number-1],
                _   => () 
            }
    
            args_number -= 1;
        }

        let config: PVOID = core::mem::transmute(&config);
        run_indirect_syscall(config)
    }
}