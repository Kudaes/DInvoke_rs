#[macro_use]
extern crate litcrypt;
use_litcrypt!();

use std::ptr;
use std::ffi::CString;
use data::{DLL_PROCESS_ATTACH, EntryPoint, LdrGetProcedureAddress, LoadLibraryA, PeMetadata, PVOID};
use libc::c_void;
use litcrypt::lc;
use winproc::Process;

use bindings::Windows::Win32::Foundation::{HINSTANCE,PSTR};

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
/// if ntdll != 0
/// {
///     println!("The base address of ntdll.dll is 0x{:X}.", ntdll);
/// }
/// ```
pub fn get_module_base_address (module_name: &str) -> i64
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

/// Retrieves the address of an exported function from the specified module.
///
/// This functions is analogous to GetProcAddress from Win32. The exported 
/// function's address is obtained by walking and parsing the PE headers of the  
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
///     println!("The address where NtCreateThread is located at is 0x{:X}.", addr);
/// }
/// ```
pub fn get_function_address(module_base_address: i64, function: &str) -> i64 {
    
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
///     let ordinal: u32 = 8; // Ordinal 8 represents the function RtlDispatchAPC
///     let addr = dinvoke::get_function_address_ordinal(ntdll, 8);    
///     println!("The address where RtlDispatchAPC is located at is 0x{:X}.", addr);
/// }
/// ```
pub fn get_function_address_ordinal (module_base_address: i64, ordinal: u32) -> i64 {

    let ret = ldr_get_procedure_address(module_base_address, "", ordinal);

    match ret {
    Ok(r) => return r,
    Err(_) => return 0, 
    }
    
}

/// Retrieves the address of an exported function from the specified module either by its name 
/// or by its ordinal number.
///
/// This functions internally calls LdrGetProcedureAddress.
///
/// In case that the function's address can't be retrieved, it will return an Err with a 
/// descriptive error message.
///
/// # Examples
///
/// ```
/// let ntdll = dinvoke::get_module_base_address("ntdll.dll");
///
/// if ntdll != 0
/// {
///     let ordinal: u32 = 8; // Ordinal 8 represents the function RtlDispatchAPC
///     let ret = dinvoke::ldr_get_procedure_address(ntdll,"", 8);
///     match ret {
///         Ok(addr) => println!("The address where RtlDispatchAPC is located at is 0x{:X}.", addr),
///         Err(e) => println!("{}",e),
///     }
///     
/// }
/// ```
pub fn ldr_get_procedure_address (module_handle: i64, function_name: &str, ordinal: u32) -> Result<i64, String> {

    unsafe 
    {   
        let mut result: i64 = 0;
        
        let module_base_address = get_module_base_address(&lc!("ntdll.dll")); 
        if module_base_address != 0
        {
            let function_address = get_function_address(module_base_address, &lc!("LdrGetProcedureAddress"));

            if function_address != 0 
            {
                let hmodule: PVOID = std::mem::transmute(module_handle);
                let func_ptr: LdrGetProcedureAddress = std::mem::transmute(function_address);  
                let return_address: *mut c_void = std::mem::transmute(&u64::default());
                let return_address: *mut PVOID = std::mem::transmute(return_address);
                let mut fun_name: *mut String = std::mem::transmute(&String::default());

                if function_name == ""
                {
                    fun_name = ptr::null_mut();
                }
                else 
                {
                    *fun_name = function_name.to_string();
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

/// Loads and retrieves a module's base address by dynamically calling LoadLibraryA.
///
///
/// It will return either the module's base address or an Err with a descriptive error message.
///
/// # Examples
///
/// ```
/// let ret = dinvoke::load_library_a("ntdll.dll");
///
///  match ret {
///      Ok(addr) => if addr != 0 {println!("ntdll.dll base address is 0x{:X}.", addr)},
///      Err(e) => println!("{}",e),
///  }
/// ```
pub fn load_library_a(module: &str) -> Result<i64, String> {

    unsafe 
    {    

        let module_base_address = get_module_base_address(&lc!("kernel32.dll")); 
        let mut result = HINSTANCE {0: 0 as isize};
        if module_base_address != 0
        {
            let function_address = get_function_address(module_base_address, &lc!("LoadLibraryA"));

            if function_address != 0 
            {
                let function_ptr: LoadLibraryA = std::mem::transmute(function_address); 
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

/// Calls the module's entry point with the option DLL_ATTACH_PROCESS.
///
/// # Examples
///
/// ```ignore
///    let pe = manualmap::read_and_map_module("c:\\some\\random\\file.dll").unwrap();
///    let ret = dinvoke::call_module_entry_point(&pe.0, pe.1);
/// ```
pub fn call_module_entry_point(pe_info: &PeMetadata, module_base_address: i64) -> Result<(), String> {

    let entry_point;
    if pe_info.is_32_bit 
    {
        entry_point = module_base_address + pe_info.opt_header_32.AddressOfEntryPoint as i64;
    }
    else 
    {
        entry_point = module_base_address + pe_info.opt_header_64.address_of_entry_point as i64;

    }

    unsafe 
    {
        let main: EntryPoint = std::mem::transmute(entry_point);
        let module = HINSTANCE {0: entry_point as isize};
        let ret = main(module, DLL_PROCESS_ATTACH, ptr::null_mut());

        if !ret.as_bool()
        {
            return Err(lc!("[x] Failed to call module's entry point (DllMain -> DLL_PROCESS_ATTACH)."));
        }

        Ok(())
    }
}

/// Dynamically calls an exported function from the specified module.
///
/// This macro will use the dinvoke crate functions to obtain an exported
/// function address of the specified module in the runtime by walking process structures 
/// and PE headers.
///
/// In case that this macro is used to call a dll entry point (DllMain), it will return true
/// or false (using the 3rd argument passed to the macro) depending on the success of the call.
/// In any other case, it will return the same data type that the called function would return
/// using the 4th argument passed to the macro.
///
/// # Example - Calling a dll entry point
///
/// ```ignore
/// let a = manualmap::read_and_map_module("c:\\some\\random\\file.dll").unwrap();
/// let ret: bool = false;
/// dinvoke::dynamic_invoke(&a.0, a.1, ret); // dinvoke::dynamic_invoke(&PeMetadata, i64, bool)
/// if ret { println!("Entry point successfully called.");}
/// ```
/// # Example - Dynamically calling LoadLibraryA
///
/// ```ignore
/// let kernel32 = manualmap::read_and_map_module("c:\\windows\\system32\\kernel32.dll").unwrap();
/// let mut ret = HINSTANCE {0: 0 as isize};
/// let function_ptr: data::LoadLibraryA;
/// let name = CString::new("ntdll.dll").expect("CString::new failed");
/// let module_name = PSTR{0: name.as_ptr() as *mut u8};
/// //dinvoke::dynamic_invoke(i64,&str,<function_type>,Option<return_type>,[arguments])
/// dinvoke::dynamic_invoke(a.1, "LoadLibraryA", function_ptr, ret, module_name);
///
/// if ret.0 != 0 { println!("ntdll base address is 0x{:X}",ret.0);}
/// ```
/// # Example - Dynamically calling with referenced arguments
///
/// ```ignore
/// let ptr = dinvoke::get_module_base_address("ntdll.dll");
/// let function_ptr: LdrGetProcedureAddress;
/// let ret: Option<i32>;
/// let hmodule: PVOID = std::mem::transmute(ptr);
/// let fun_name: *mut String = ptr::null_mut();
/// let ordinal = 8 as u32;
/// let return_address: *mut c_void = std::mem::transmute(&u64::default());
/// let return_address: *mut PVOID = std::mem::transmute(return_address);
/// //dinvoke::dynamic_invoke(i64,&str,<function_type>,Option<return_type>,[arguments])
/// dinvoke::dynamic_invoke!(ptr,"LdrGetProcedureAddress",function_ptr,ret,hmodule,fun_name,ordinal,return_address);
/// match ret {
///     Some(x) => if x == 0 {println!("RtlDispatchAPC is located at the address: 0x{:X}",*return_address as u64);},
///     None => println!("Error calling LdrGetProcedureAddress"),
/// }
/// ```
#[macro_export]
macro_rules! dynamic_invoke {

    ($a:expr, $b:expr, $c:expr) => {
        let ret = $crate::call_module_entry_point(&$a,$b);

        match ret {
            Ok(_) => $c = true,
            Err(_) => $c = false,
        }

    };

    ($a:expr, $b:expr, $c:expr, $d:expr, $($e:tt)*) => {

        let function_ptr = $crate::get_function_address($a, $b);
        if function_ptr != 0
        {
            $c = std::mem::transmute(function_ptr);
            $d = Some($c($($e)*));
        }
        else
        {
            $d = None;
        }

    };
}