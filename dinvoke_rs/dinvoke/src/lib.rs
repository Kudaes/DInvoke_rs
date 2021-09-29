#[macro_use]
extern crate litcrypt;
use_litcrypt!();



use std::ptr;
use std::ffi::CString;
use libc::c_void;
use litcrypt::lc;
use winproc::Process;

use bindings::Windows::Win32::Foundation::{HINSTANCE,PSTR};


type PVOID = *mut c_void;

/// Returns the base address of a module loaded in the current process.
///
/// # Examples
///
/// ```
/// let ntdll = dinvoke::get_module_base_address(&"ntdll.dll".to_string());
///
/// if ntdll != 0
/// {
///     println!("The base address of ntdll.dll is 0x{:X}.", ntdll);
/// }
/// ```
pub fn get_module_base_address (module_name: &String) -> i64
{
    let process = Process::current();
    let modules = process.module_list().unwrap();
    for m in modules
    {
        if m.name().unwrap().to_lowercase() == module_name.to_ascii_lowercase()
        {
            let handle = m.handle();
            return handle as i64;
        }
    }

    0
}

pub fn get_function_address(module_base_address: i64, function: String) -> i64 {
    
    let mut function_ptr:*mut i32 = ptr::null_mut();

    unsafe
    {

        let pe_header = *((module_base_address + 0x3C) as *mut i32);
        let opt_header: i64 = module_base_address + (pe_header as i64) + 0x18;
        let magic = *(opt_header as *mut i16);
        let p_export: i64;

        if magic == 0x010b 
        {
            p_export = opt_header + 0x60;
        } 
        else 
        {
            p_export = opt_header + 0x70;
        }

        let export_rva = *(p_export as *mut i32);
        let ordinal_base = *((module_base_address + export_rva as i64 + 0x10) as *mut i32);
        let number_of_names = *((module_base_address + export_rva as i64 + 0x18) as *mut i32);
        let functions_rva = *((module_base_address + export_rva as i64 + 0x1C) as *mut i32);
        let names_rva = *((module_base_address + export_rva as i64 + 0x20) as *mut i32);
        let ordinals_rva = *((module_base_address + export_rva as i64 + 0x24) as *mut i32);

        for x in 0..number_of_names 
        {

            let address = *((module_base_address + names_rva as i64 + x as i64 * 4) as *mut i32);
            let mut function_name_ptr = (module_base_address + address as i64) as *mut u8;
            let mut function_name: String = "".to_string();

            while *function_name_ptr as char != '\0' // null byte
            { 
                function_name.push(*function_name_ptr as char);
                function_name_ptr = function_name_ptr.add(1);
            }

            if function_name.to_lowercase() == function.to_lowercase() 
            {
                let function_ordinal = *((module_base_address + ordinals_rva as i64 + x as i64 * 2) as *mut i16) as i32 + ordinal_base;
                let function_rva = *(((module_base_address + functions_rva as i64 + (4 * (function_ordinal - ordinal_base)) as i64 )) as *mut i32);
                function_ptr = (module_base_address + function_rva as i64) as *mut i32;

                break;
            }

        }

        let mut ret: i64 = 0;

        if function_ptr != ptr::null_mut()
        {
            ret = function_ptr as i64;
        }
    
        ret

    }
}

pub fn get_function_address_ordinal (module_base_address: i64, ordinal: u32) -> i64 {

    let ret = ldr_get_procedure_address(module_base_address, "".to_string(), ordinal);

    match ret {
    Ok(r) => return r,
    Err(_) => return 0, 
    }
    
}

pub fn ldr_get_procedure_address (module_handle: i64, function_name: String, ordinal: u32) -> Result<i64, String> {

    unsafe 
    {   
        let mut result: i64 = 0;
        
        let module_base_address = get_module_base_address(&lc!("ntdll.dll".to_string())); 
        if module_base_address != 0
        {
            let function_address = get_function_address(module_base_address, lc!("LdrGetProcedureAddress".to_string()));

            if function_address != 0 
            {
                let hmodule: PVOID = std::mem::transmute(module_handle);
                let func_ptr: unsafe extern "system" fn (PVOID, *mut String, u32, *mut PVOID) -> i32 = std::mem::transmute(function_address); //LdrGetProcedureAddress 
                let return_address: *mut c_void = std::mem::transmute(&u64::default());
                let return_address: *mut PVOID = std::mem::transmute(return_address);
                let mut fun_name: *mut String = std::mem::transmute(&String::default());

                if function_name == ""
                {
                    fun_name = ptr::null_mut();
                }
                else 
                {
                    *fun_name = function_name;
                }

                let ret = func_ptr(hmodule, fun_name, ordinal, return_address);

                if ret == 0
                {
                    result = *return_address as i64;
                }
            }
            else 
            {
                return Err(lc!("[x] Error obtaining LdrGetProcedureAddress address."));
            }
        }
        else 
        {
            return Err(lc!("[x] Error obtaining ntdll.dll base address."));
        }

        Ok(result)
    }
}

pub fn load_library_a(module: &String) -> Result<i64, String> {

    unsafe 
    {    

        let module_base_address = get_module_base_address(&lc!("kernel32.dll".to_string())); 
        let mut result = HINSTANCE {0: 0 as isize};
        if module_base_address != 0
        {
            let function_address = get_function_address(module_base_address, lc!("LoadLibraryA".to_string()));

            if function_address != 0 
            {
                let function_ptr: extern "system" fn (PSTR) -> HINSTANCE = std::mem::transmute(function_address); 
                let name = CString::new(module.to_string()).expect("CString::new failed");
                let function_name = PSTR{0: name.as_ptr() as *mut u8};

                result = function_ptr(function_name);
            }
            else 
            {
                return Err(lc!("[x] Error obtaining LoadLibraryA address."));
            }
        } 
        else 
        {
            return Err(lc!("[x] Error obtaining kernel32.dll base address."));
        }

        Ok(result.0 as i64)
    }

}
