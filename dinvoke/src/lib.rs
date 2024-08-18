#[macro_use]
extern crate litcrypt2;
use_litcrypt!();

use libc::c_void;
use litcrypt2::lc;
use std::cell::UnsafeCell;
use std::mem::size_of;
use std::panic;
use std::{collections::HashMap, ptr};
use std::ffi::{CString, OsString};
use std::os::windows::ffi::OsStringExt;
use data::MAX_PATH;
#[cfg(target_arch = "x86_64")]
use nanorand::{WyRand, Rng};
use winapi::um::psapi::{EnumProcessModules, GetModuleBaseNameW, GetModuleFileNameExW};
use winapi::shared::ntdef::LARGE_INTEGER;
use windows::Win32::Foundation::BOOL;
use windows::Win32::Security::SECURITY_ATTRIBUTES;
#[cfg(target_arch = "x86_64")]
use windows::Win32::System::Diagnostics::Debug::{GetThreadContext,SetThreadContext};
use windows::Win32::System::Memory::MEMORY_BASIC_INFORMATION;
use windows::Win32::System::SystemInformation::SYSTEM_INFO;
use windows::Win32::System::Threading::PROCESS_BASIC_INFORMATION;
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
#[cfg(target_arch = "x86_64")]
use windows::Win32::{Foundation::{HANDLE, HINSTANCE,UNICODE_STRING}, System::Threading::{GetCurrentProcess,GetCurrentThread}};
#[cfg(target_arch = "x86")]
use windows::Win32::{Foundation::{HANDLE, HINSTANCE,UNICODE_STRING}, System::Threading::GetCurrentProcess};
#[cfg(target_arch = "x86_64")]
use data::{ApiSetNamespace, ApiSetNamespaceEntry, ApiSetValueEntry, ClientId, EntryPoint, ExceptionHandleFunction, ExceptionPointers, LptopLevelExceptionFilter, NtAllocateVirtualMemoryArgs, NtCreateThreadExArgs, NtOpenProcessArgs, NtProtectVirtualMemoryArgs, NtWriteVirtualMemoryArgs, PeMetadata, PsAttributeList, PsCreateInfo, CONTEXT, DLL_PROCESS_ATTACH, EAT, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE, PROCESS_QUERY_LIMITED_INFORMATION, PVOID, TLS_OUT_OF_INDEXES};
#[cfg(target_arch = "x86")]
use data::{ApiSetNamespace, ApiSetNamespaceEntry, ApiSetValueEntry, ClientId, EntryPoint, LptopLevelExceptionFilter, PeMetadata, PsAttributeList, PsCreateInfo, DLL_PROCESS_ATTACH, EAT, PAGE_EXECUTE_READWRITE, PVOID, TLS_OUT_OF_INDEXES};

#[cfg(target_arch = "x86_64")]
static mut HARDWARE_BREAKPOINTS: bool = false;
#[cfg(target_arch = "x86_64")]
static mut HARDWARE_EXCEPTION_FUNCTION: ExceptionHandleFunction = ExceptionHandleFunction::NtOpenProcess;
#[cfg(target_arch = "x86_64")]
static mut NT_ALLOCATE_VIRTUAL_MEMORY_ARGS: NtAllocateVirtualMemoryArgs = NtAllocateVirtualMemoryArgs{handle: HANDLE {0: -1}, base_address: ptr::null_mut()};
#[cfg(target_arch = "x86_64")]
static mut NT_OPEN_PROCESS_ARGS: NtOpenProcessArgs = NtOpenProcessArgs{handle: ptr::null_mut(), access:0, attributes: ptr::null_mut(), client_id: ptr::null_mut()};
#[cfg(target_arch = "x86_64")]
static mut NT_PROTECT_VIRTUAL_MEMORY_ARGS: NtProtectVirtualMemoryArgs = NtProtectVirtualMemoryArgs{handle: HANDLE {0: -1}, base_address: ptr::null_mut(), size: ptr::null_mut(), protection: 0};
#[cfg(target_arch = "x86_64")]
static mut NT_WRITE_VIRTUAL_MEMORY_ARGS: NtWriteVirtualMemoryArgs = NtWriteVirtualMemoryArgs{handle: HANDLE {0: -1}, base_address: ptr::null_mut(), buffer: ptr::null_mut(), size: 0usize};
#[cfg(target_arch = "x86_64")]
static mut NT_CREATE_THREAD_EX_ARGS: NtCreateThreadExArgs = NtCreateThreadExArgs{thread:ptr::null_mut(), access: 0, attributes: ptr::null_mut(), process: HANDLE {0: -1}};
static mut HOOKED_FUNCTIONS_INFO: Vec<(usize,Vec<u8>)> = vec![];


/// Enables or disables the use of exception handlers in
/// combination with hardware breakpoints.
#[cfg(target_arch = "x86_64")]
pub fn use_hardware_breakpoints(value: bool)
{
    unsafe
    {
        HARDWARE_BREAKPOINTS = value;
    }
} 

/// It sets a hardware breakpoint on a certain memory address.
///
/// # Examples
///
/// ```
/// let ntdll = dinvoke::get_module_base_address("ntdll.dll");
/// let nt_open_process = dinvoke::get_function_address(ntdll, "NtOpenProcess");
/// let instruction_addr = dinvoke::find_syscall_address(nt_open_process);
/// dinvoke::set_hardware_breakpoint(instruction_addr);
#[cfg(target_arch = "x86_64")]
pub fn set_hardware_breakpoint(address: usize) 
{
    unsafe
    {
        let mut context = CONTEXT::default();   
        context.ContextFlags = 0x100000 | 0x10; // CONTEXT_DEBUG_REGISTERS
        let mut lp_context: *mut windows::Win32::System::Diagnostics::Debug::CONTEXT = std::mem::transmute(&context);
        let _ = GetThreadContext(GetCurrentThread(), lp_context);

        let context: *mut CONTEXT = std::mem::transmute(lp_context);
        (*context).Dr0 = address as u64;
        (*context).Dr6 = 0;
        (*context).Dr7 = (*context).Dr7 & !(((1 << 2) - 1) << 16); // 0xfffcffff ->  Break on instruction execution only
        (*context).Dr7 = (*context).Dr7 & !(((1 << 2) - 1) << 18); // 0xfff3ffff 
        (*context).Dr7 = ((*context).Dr7 & !(((1 << 1) - 1) << 0)) | (1 << 0); // 0xfffffffe 

        (*context).ContextFlags = 0x100000 | 0x10;
        lp_context = std::mem::transmute(context);
        
        let _ = SetThreadContext(GetCurrentThread(), lp_context );
    }
}

/// This function acts as an Exception Handler, and should be combined with a hardware breakpoint.
///
/// Whenever the HB gets triggered, this function will be executed. This is meant to be used in order
/// to spoof syscalls parameters.
#[cfg(target_arch = "x86_64")]
pub unsafe extern "system" fn breakpoint_handler (exceptioninfo: *mut ExceptionPointers) -> i32
{
    if (*(*(exceptioninfo)).exception_record).ExceptionCode.0 as u32 == 0x80000004 // STATUS_SINGLE_STEP
    {
        if ((*(*exceptioninfo).context_record).Dr7 & 1) == 1
        {
            if (*(*exceptioninfo).context_record).Rip == (*(*exceptioninfo).context_record).Dr0
            {
                (*(*exceptioninfo).context_record).Dr0 = 0; // Remove the breakpoint
                match HARDWARE_EXCEPTION_FUNCTION
                {
                    ExceptionHandleFunction::NtAllocateVirtualMemory =>
                    { 
                        (*(*exceptioninfo).context_record).R10 = NT_ALLOCATE_VIRTUAL_MEMORY_ARGS.handle.0 as u64;
                        (*(*exceptioninfo).context_record).Rdx = std::mem::transmute(NT_ALLOCATE_VIRTUAL_MEMORY_ARGS.base_address);

                    }, 
                    ExceptionHandleFunction::NtProtectVirtualMemory => 
                    {
                        (*(*exceptioninfo).context_record).R10 = NT_PROTECT_VIRTUAL_MEMORY_ARGS.handle.0 as u64;
                        (*(*exceptioninfo).context_record).Rdx = std::mem::transmute(NT_PROTECT_VIRTUAL_MEMORY_ARGS.base_address);
                        (*(*exceptioninfo).context_record).R8 = std::mem::transmute(NT_PROTECT_VIRTUAL_MEMORY_ARGS.size);
                        (*(*exceptioninfo).context_record).R9 = NT_PROTECT_VIRTUAL_MEMORY_ARGS.protection as u64;

                    },
                    ExceptionHandleFunction::NtOpenProcess =>
                    {
                        (*(*exceptioninfo).context_record).R10 = std::mem::transmute(NT_OPEN_PROCESS_ARGS.handle);
                        (*(*exceptioninfo).context_record).Rdx = NT_OPEN_PROCESS_ARGS.access as u64;
                        (*(*exceptioninfo).context_record).R8 = std::mem::transmute(NT_OPEN_PROCESS_ARGS.attributes);
                        (*(*exceptioninfo).context_record).R9 = std::mem::transmute(NT_OPEN_PROCESS_ARGS.client_id);

                    },
                    ExceptionHandleFunction::NtWriteVirtualMemory =>
                    {
                        (*(*exceptioninfo).context_record).R10 = NT_WRITE_VIRTUAL_MEMORY_ARGS.handle.0 as u64;
                        (*(*exceptioninfo).context_record).Rdx = std::mem::transmute(NT_WRITE_VIRTUAL_MEMORY_ARGS.base_address);
                        (*(*exceptioninfo).context_record).R8 = std::mem::transmute(NT_WRITE_VIRTUAL_MEMORY_ARGS.buffer);
                        (*(*exceptioninfo).context_record).R9 = NT_WRITE_VIRTUAL_MEMORY_ARGS.size as u64;
                    },
                    ExceptionHandleFunction::NtCreateThreadEx =>
                    {
                        (*(*exceptioninfo).context_record).R10 = std::mem::transmute(NT_CREATE_THREAD_EX_ARGS.thread);
                        (*(*exceptioninfo).context_record).Rdx = NT_CREATE_THREAD_EX_ARGS.access as u64;
                        (*(*exceptioninfo).context_record).R8 = std::mem::transmute(NT_CREATE_THREAD_EX_ARGS.attributes);
                        (*(*exceptioninfo).context_record).R9 = NT_CREATE_THREAD_EX_ARGS.process.0 as u64;
                    }                  
                }
            }
        }
        return -1; // EXCEPTION_CONTINUE_EXECUTION
    }
    0 // EXCEPTION_CONTINUE_SEARCH
}

/// Inserts an inline hook at a specified source memory address to redirect execution flow to a
/// destination memory address. This function is used to hook a function and redirect its execution
/// to a custom handler.
///
/// # Arguments
///
/// * `src_address` - The source memory address where the inline hook will be inserted.
///   This should be the starting address of the function to be hooked.
/// * `dst_address` - The destination memory address where the execution will be redirected.
///   This is typically the address of the hook handler function.
///
/// # Returns
///
/// Returns `true` if the hook is successfully inserted, `false` otherwise.
///
/// # Side Effects
///
/// If the hook is successfully established, the information regarding the new hook is stored,
/// allowing it to be easily removed later by calling the `unhook_function`.
///
/// # Example
///
/// ```
/// fn main() {
///     let kernelbase = dinvoke::get_module_base_address("kernelbase.dll");
///     let load_addr = dinvoke::get_function_address(kernelbase, "LoadLibraryA");
///     let hook_result = dinvoke::hook_function(load_addr as _, load_library_handler as *const () as _);
///
///     if hook_result {
///         println!("Hook inserted successfully.");
///     } else {
///         println!("Failed to insert hook.");
///     }
/// }
/// 
/// fn load_library_handler(library_name:*mut u8) -> usize
/// {
///     DoStuff();
/// }
/// ```
pub fn hook_function(src_address: usize, dst_address: usize) -> bool
{
    unsafe 
    {
        let original_address = src_address;
        let handle = HANDLE(-1);
        let base_address: *mut PVOID = std::mem::transmute(&original_address);
        let size = 4096 as usize; 
        let size: *mut usize = std::mem::transmute(&size);
        let o = u32::default();
        let old_protection: *mut u32 = std::mem::transmute(&o);

        let z = nt_protect_virtual_memory( 
            handle,
            base_address,
            size,
            PAGE_EXECUTE_READWRITE,
            old_protection
        );

        if z != 0 {
            return false;
        }

        let ntop_ptr = src_address as *mut u8;
        let mut original_bytes: Vec<u8> = vec![]; 
        if cfg!(target_pointer_width = "64") 
        {
            for i in 0..=12
            {
                let b = *(ntop_ptr.add(i));
                original_bytes.push(b);
            }

            *ntop_ptr = 0x49;
            *(ntop_ptr.add(1)) = 0xBB;
            *(ntop_ptr.add(2) as *mut usize) = dst_address;
            *(ntop_ptr.add(10)) = 0x41;
            *(ntop_ptr.add(11)) = 0xFF;
            *(ntop_ptr.add(12)) = 0xE3;
        } 
        else 
        {
            for i in 0..=5
            {
                let b = *(ntop_ptr.add(i));
                original_bytes.push(b);
            }

            *ntop_ptr = 0x68;
            *(ntop_ptr.add(1) as *mut usize) = dst_address;
            *(ntop_ptr.add(5)) = 0xC3
        } 

        HOOKED_FUNCTIONS_INFO.push((src_address, original_bytes));

        let u = 0u32;
        let unused: *mut u32 = std::mem::transmute(&u);

        let z = nt_protect_virtual_memory(
            handle,
            base_address,
            size,
            *old_protection,
            unused
        );

        if z != 0 {
            return false;
        }

        true
    }
}

/// Removes an inline hook previously inserted by `hook_function` at a specified memory address.
/// This function checks if the hook exists at the given address and, if so, removes it by restoring
/// the original content that was replaced during the hooking process.
///
/// # Arguments
///
/// * `address` - The memory address where the hook is supposedly located.
///
/// # Returns
///
/// Returns `true` if the hook was successfully found and removed, `false` otherwise.
///
/// # Example
///
/// ```
/// fn main() {
///     let hook_address: usize = 0x123456;  // Example address where a hook might be located
///
///     let unhook_result = unhook_function(hook_address);
///     if unhook_result {
///         println!("Hook removed successfully.");
///     } else {
///         println!("Failed to remove hook.");
///     }
/// }
/// ```
pub fn unhook_function(address: usize) -> bool
{
    unsafe
    {
        let mut unhook_info = (0, vec![]);
        let mut index = 0;
        for (i, element) in HOOKED_FUNCTIONS_INFO.iter().enumerate()
        {
            if element.0 == address 
            {
                unhook_info = (element.0,element.1.to_vec());
                index = i;
                break;
            }
        }

        if unhook_info.0 == 0 {
            return false;
        }

        let original_address = unhook_info.0;
        let handle = HANDLE(-1);
        let base_address: *mut PVOID = std::mem::transmute(&original_address);
        let size = 4096 as usize;   
        let size: *mut usize = std::mem::transmute(&size);
        let o = u32::default();
        let old_protection: *mut u32 = std::mem::transmute(&o);

        let z = nt_protect_virtual_memory( 
            handle,
            base_address,
            size,
            PAGE_EXECUTE_READWRITE,
            old_protection
        );

        if z != 0 {
            return false;
        }

        let ptr = unhook_info.0 as *mut u8;
        for i in 0..unhook_info.1.len()
        {
            let addr = ptr.add(i);
            *addr = unhook_info.1[i];
        }

        let u = 0u32;
        let unused: *mut u32 = std::mem::transmute(&u);

        let z = nt_protect_virtual_memory(
            handle,
            base_address,
            size,
            *old_protection,
            unused
        );

        if z != 0 {
            return false;
        }

        HOOKED_FUNCTIONS_INFO.remove(index);

        true
    }

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
/// if ntdll != 0
/// {
///     println!("The base address of ntdll.dll is 0x{:X}.", ntdll);
/// }
/// ```
pub fn get_module_base_address (module_name: &str) -> usize
{
    let modules = get_modules_list().unwrap();

    for m in modules 
    {
        let name = get_module_name(m);
        let path = get_module_path(m);

        if name.is_err() || path.is_err() {
            continue;
        }

        if name.unwrap().to_ascii_lowercase() == module_name.to_ascii_lowercase() ||
            path.unwrap().to_ascii_lowercase() == module_name.to_ascii_lowercase()
        {
            return m;
        }
    }

    0
}

fn get_modules_list() -> Result<Vec<usize>, u32> 
{
    unsafe 
    {
        let mut mod_handles: Vec<usize> = Vec::new();
        let mut reserved = 0;
        let mut needed = 0;
        let current_process = HANDLE(-1);
        let current_process: *mut winapi::ctypes::c_void = std::mem::transmute(current_process);

        // Code extracted from winproc
        let enum_mods = |mod_handles: &mut Vec<usize>, needed: *mut u32| {
            let cb = mod_handles.len() as u32;

            let res = EnumProcessModules(current_process, mod_handles.as_mut_ptr() as _, cb, needed);

            if res == 0 {
                Err(get_last_error())
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
}

fn get_module_name(hmodule: usize) -> Result<String,u32>
{
    unsafe 
    {
        let current_process = HANDLE(-1);
        let current_process: *mut winapi::ctypes::c_void = std::mem::transmute(current_process);
        let mut buffer: [u16; MAX_PATH as _] = std::mem::zeroed();

        let res = GetModuleBaseNameW(current_process, hmodule as _, buffer.as_mut_ptr(), MAX_PATH);
        if res == 0 {
            Err(get_last_error())
        } else {
            // Code extracted from winproc
            Ok(OsString::from_wide(&buffer[0..res as usize])
                    .to_string_lossy()
                    .into_owned())
        }
    }
}

fn get_module_path(hmodule: usize) -> Result<String,u32>
{
    unsafe 
    {
        let current_process = HANDLE(-1);
        let current_process: *mut winapi::ctypes::c_void = std::mem::transmute(current_process);
        let mut buffer: [u16; MAX_PATH as _] = std::mem::zeroed();

        let res = GetModuleFileNameExW(current_process, hmodule as _, buffer.as_mut_ptr(), MAX_PATH);
        if res == 0 {
            Err(get_last_error())
        } else {
            // Code extracted from winproc
            Ok(OsString::from_wide(&buffer[0..res as usize])
                    .to_string_lossy()
                    .into_owned())
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
///     println!("The address where NtCreateThread is located at is 0x{:X}.", addr);
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

        if magic == 0x010b 
        {
            p_export = opt_header + 0x60;
        } 
        else 
        {
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
            let mut function_name: String = "".to_string();

            while *function_name_ptr as char != '\0' // null byte
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

        if function_ptr != ptr::null_mut()
        {
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
        let mut forwarded_names = "".to_string();

        loop 
        {
            if *ptr as char != '\0'
            {
                forwarded_names.push(*ptr as char);
            }
            else 
            {
                break;    
            }

            ptr = ptr.add(1);
            c = c - 1;

            // Assume there wont be an exported address with len > 100
            if c == 0
            {
                return function_ptr as usize;
            }

        }

        let values: Vec<&str> = forwarded_names.split(".").collect();
        if values.len() != 2
        {
            return function_ptr as usize;
        }

        let mut forwarded_module_name = values[0].to_string();
        let forwarded_export_name = values[1].to_string();

        let api_set = get_api_mapping();

        let prev_hook = panic::take_hook();
        panic::set_hook(Box::new(|_| {}));
        let result = panic::catch_unwind(|| {
            format!("{}{}",&forwarded_module_name[..forwarded_module_name.len() - 2], ".dll");
        });
        panic::set_hook(prev_hook);

        if result.is_err()
        {
            return function_ptr as usize;
        }

        let lookup_key = format!("{}{}",&forwarded_module_name[..forwarded_module_name.len() - 2], ".dll");

        if api_set.contains_key(&lookup_key)
        {
            forwarded_module_name = match api_set.get(&lookup_key) {
                Some(x) => x.to_string(),
                None => {forwarded_module_name}
            };
        }
        else 
        {
            forwarded_module_name = forwarded_module_name + ".dll";
        }

        let mut module = get_module_base_address(&forwarded_module_name);

        // If the module is not already loaded, we try to load it dynamically calling LoadLibraryA
        if module == 0
        {
            module = load_library_a(&forwarded_module_name);
        }

        if module != 0
        {
            return get_function_address(module, &forwarded_export_name);
        }

        function_ptr as usize
    }
}

pub fn get_api_mapping() -> HashMap<String,String> {

    unsafe 
    {
        let handle = GetCurrentProcess();
        let p = PROCESS_BASIC_INFORMATION::default();
        let process_information: *mut c_void = std::mem::transmute(&p);
        let _ret = nt_query_information_process(
            handle, 
            0, 
            process_information,  
            size_of::<PROCESS_BASIC_INFORMATION>() as u32, 
            ptr::null_mut());
        
        let _r = close_handle(handle);

        let process_information_ptr: *mut PROCESS_BASIC_INFORMATION = std::mem::transmute(process_information);

        let api_set_map_offset: usize;

        if size_of::<usize>() == 4
        {
            api_set_map_offset = 0x38;
        }
        else 
        {
            api_set_map_offset = 0x68;
        }

        let mut api_set_dict: HashMap<String,String> = HashMap::new();

        let api_set_namespace_ptr = *(((*process_information_ptr).PebBaseAddress as usize + api_set_map_offset) as *mut usize);
        let api_set_namespace_ptr: *mut ApiSetNamespace = std::mem::transmute(api_set_namespace_ptr);
        let namespace = *api_set_namespace_ptr; 

        for i in 0..namespace.count
        {

            let set_entry_ptr = (api_set_namespace_ptr as usize + namespace.entry_offset as usize + (i * size_of::<ApiSetNamespaceEntry>() as i32) as usize) as *mut ApiSetNamespaceEntry;
            let set_entry = *set_entry_ptr;

            let mut api_set_entry_name_ptr = (api_set_namespace_ptr as usize + set_entry.name_offset as usize) as *mut u8;
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
                let value = (api_set_namespace_ptr as usize + set_entry.value_offset as usize) as *mut u8;
                set_value_ptr = std::mem::transmute(value);
            }
            else if set_entry.value_length > 1
            {
                for x in 0..set_entry.value_length 
                {
                    let host_ptr = (api_set_entry_name_ptr as usize + set_entry.value_offset as usize + size_of::<ApiSetValueEntry>() as usize * x as usize) as *mut u8;
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
                        set_value_ptr = (api_set_namespace_ptr as usize + set_entry.value_offset as usize + size_of::<ApiSetValueEntry>() as usize * x as usize) as *mut ApiSetValueEntry;
                    }
                }

                if set_value_ptr == ptr::null_mut()
                {
                    set_value_ptr = (api_set_namespace_ptr as usize + set_entry.value_offset as usize) as *mut ApiSetValueEntry;
                }
            }

            let set_value = *set_value_ptr;
            let mut api_set_value: String = "".to_string();
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

/// Returns a BTreeMap<usize,String> composed of pairs (memory address, function name)
/// with all the Nt exported functions on ntdll.dll. 
///
/// This functions will only return valid data if the parameter passed is the base address of
/// ntdll.dll. This function is usefull to dynamically get a syscall id as it is shown in the
/// example.
///
/// # Examples
///
/// ```
/// let ntdll = dinvoke::get_module_base_address("ntdll.dll");
///
/// if ntdll != 0
/// {
///     let eat = dinvoke::get_ntdll_eat(ntdll);  
///     let mut j = 0;  
///     for (a,b) in eat.iter()
///     {
///         if b == "NtCreateThreadEx"
///         {
///             println!("The syscall id for NtCreateThreadEx is {}.",j);
///             break;
///         }
///         j = j + 1;
///     }
/// }
/// ```
pub fn get_ntdll_eat(module_base_address: usize) -> EAT {

    unsafe
    {
        let mut eat: EAT = EAT::default();

        let mut function_ptr:*mut i32;
        let pe_header = *((module_base_address + 0x3C) as *mut i32);
        let opt_header: usize = module_base_address + (pe_header as usize) + 0x18;
        let magic = *(opt_header as *mut i16);
        let p_export: usize;

        if magic == 0x010b 
        {
            p_export = opt_header + 0x60;
        } 
        else 
        {
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
            let mut function_name: String = "".to_string();

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

/// Returns the syscall id that correspond to the function specified.
///
/// This functions will return -1 in case that the syscall id of the specified function
/// could not be retrieved.
///
/// # Examples
///
/// ```
/// let ntdll = dinvoke::get_module_base_address("ntdll.dll");
///
/// if ntdll != 0
/// {
///     let eat = dinvoke::get_ntdll_eat(ntdll);  
///     let id = dinvoke::get_syscall_id(eat, "NtCreateThreadEx");
///     
///     if id != -1
///     {
///         println!("The syscall id for NtCreateThreadEx is {}.",id);
///     }
/// }
/// ```
pub fn get_syscall_id(eat: &EAT, function_name: &str) -> u32 {

    let mut i = 0;
    for (_a,b) in eat.iter()
    {
        if b == function_name
        {
            return i;
        }

        i = i + 1;
    }

    u32::MAX
}

/// Retrieves the memory address of a syscall instruction.
///
/// It expects the memory address of the function as a parameter, and 
/// it will iterate over each following byte until it finds the value 0x0F05.
/// 
/// It will return either the memory address of the syscall instruction or zero in case that it
/// wasn't found.
///
/// # Examples
///
/// ```
/// let ntdll = dinvoke::get_module_base_address("ntdll.dll");
/// let nt_open_process = dinvoke::get_function_address(ntdll, "NtOpenProcess");
/// let syscall_addr = dinvoke::find_syscall_address(nt_open_process);
/// ```
pub fn find_syscall_address(address: usize) -> usize
{
    unsafe
    {
        let stub: [u8;2] = [ 0x0F, 0x05 ];
        let mut ptr:*mut u8 = address as *mut u8;
        for _i in 0..23
        {
            if *(ptr.add(1)) == stub[0] && *(ptr.add(2)) == stub[1]
            {
                return ptr.add(1) as usize;
            }

            ptr = ptr.add(1);
        }
    }

    0usize
}

/// Given a valid syscall id, it will allocate the required shellcode to execute 
/// that specific syscall.
///
/// This functions will return the memory address where the shellcode has been written. If any 
/// error has ocurred, it will return 0.
///
/// # Examples
///
/// ```
/// let ntdll = dinvoke::get_module_base_address("ntdll.dll");
///
/// if ntdll != 0
/// {
///     let eat = dinvoke::get_ntdll_eat(ntdll);  
///     let id = dinvoke::get_syscall_id(eat, "NtCreateThreadEx");
///     
///     if id != -1
///     {
///         let addr = dinvoke::prepare_syscall(id as u32);
///         println!("NtCreateThreadEx syscall ready to be executed at address 0x{:X}", addr);
///     }
/// }
/// ```
#[cfg(target_arch = "x86_64")]
pub fn prepare_syscall(id: u32, eat: EAT) -> usize {

    let mut sh: [u8;21] = 
    [ 
        0x4C, 0x8B, 0xD1,
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x41, 0xFF, 0xE3
    ];

    unsafe 
    {
        if id == u32::MAX
        {
            return 0;
        }
        
        let mut ptr: *mut u8 = std::mem::transmute(&id);

        for i in 0..4
        {
            sh[4 + i] = *ptr;
            ptr = ptr.add(1);
        }

        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        let export = eat.iter().skip(id as usize).next().unwrap();
        let mut function_addr = get_function_address(ntdll, export.1);

        if function_addr == 0
        {
            return 0;
        }

        let mut syscall_addr = find_syscall_address(function_addr);
        if syscall_addr == 0
        {
            let max_range = eat.len();
            let mut function = &"".to_string();
            let mut rng = WyRand::new();
            for _ in 0..5
            {
                for s in eat.values()
                {
                    let index = rng.generate_range(0_usize..=max_range) as usize;
        
                    if index < max_range / 5
                    {
                        function = s;
                        break;
                    }
                }
        
                function_addr = get_function_address(ntdll, function);
        
                if function_addr == 0
                {
                    return 0;
                }
        
                syscall_addr = find_syscall_address(function_addr);
                if syscall_addr != 0
                {
                    break;
                }
            }

            if syscall_addr == 0
            {
                return 0;
            }
        }

        let mut syscall_ptr: *mut u8 = std::mem::transmute(&syscall_addr);

        for j in 0..8
        {
            sh[10 + j] = *syscall_ptr;
            syscall_ptr = syscall_ptr.add(1);
        }

        let handle = GetCurrentProcess();
        let b = usize::default();
        let base_address: *mut PVOID = std::mem::transmute(&b);
        let nsize: usize = sh.len() as usize;
        let s = nsize;
        let size: *mut usize = std::mem::transmute(&s);
        let o = u32::default();
        let old_protection: *mut u32 = std::mem::transmute(&o);
        let ret = nt_allocate_virtual_memory(handle, base_address, 0, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        
        if ret != 0
        {
            return 0;
        }
        
        let buffer: *mut c_void = std::mem::transmute(sh.as_ptr());
        let b = usize::default();
        let bytes_written: *mut usize = std::mem::transmute(&b);
        let ret = nt_write_virtual_memory(handle, *base_address, buffer, nsize, bytes_written);

        if ret != 0
        {
            return 0;
        }

        let ret = nt_protect_virtual_memory(handle, base_address, size, PAGE_EXECUTE_READ, old_protection);

        let _r = close_handle(handle);
        
        if ret != 0
        {
            return 0;
        }

        *base_address as usize
    }


}

/// Calls the module's entry point with the option DLL_ATTACH_PROCESS.
///
/// # Examples
///
/// ```ignore
///    let pe = manualmap::read_and_map_module("c:\\some\\random\\file.dll").unwrap();
///    let ret = dinvoke::call_module_entry_point(pe.0, pe.1);
/// 
///    match ret
///    {
///         Ok(()) => println!("Module entry point successfully executed."),
///         Err(e) => println!("Error ocurred: {}", e)
///    }
/// ```
pub fn call_module_entry_point(pe_info: PeMetadata, module_base_address: usize) -> Result<(), String> {

    let entry_point;
    if pe_info.is_32_bit {
        entry_point = module_base_address + pe_info.opt_header_32.AddressOfEntryPoint as usize;
    }
    else {
        entry_point = module_base_address + pe_info.opt_header_64.address_of_entry_point as usize;

    }

    unsafe 
    {
        let main: EntryPoint = std::mem::transmute(entry_point);
        let module = HINSTANCE {0: entry_point as isize};
        let ret = main(module, DLL_PROCESS_ATTACH, ptr::null_mut());

        if !ret.as_bool() {
            return Err(lc!("[x] Failed to call module's entry point (DllMain -> DLL_PROCESS_ATTACH)."));
        }

        Ok(())
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
///     if addr != 0
///     { 
///         println!("The function with ordinal 8 is located at 0x{:X}.", addr);
///     }
/// }
/// ```
pub fn get_function_address_by_ordinal(module_base_address: usize, ordinal: u32) -> usize 
{
    let ret = ldr_get_procedure_address(module_base_address, "", ordinal);
    ret    
}

/// Call NtCreateUserProcess to fork the current process.
/// Inheritable objects are inherited by the child process (PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT).
/// 
/// The function returns an NTSTATUS.
pub fn fork() -> i32
{
   unsafe
   {
      let process_handle = HANDLE::default();
      let thread_handle = HANDLE::default();
      let process_handle: *mut HANDLE = std::mem::transmute(&process_handle);
      let thread_handle: *mut HANDLE = std::mem::transmute(&thread_handle);
      let mut create_info: PsCreateInfo = std::mem::zeroed();
      create_info.size = size_of::<PsCreateInfo>();
      let ps_create_info: *mut PsCreateInfo = std::mem::transmute(&create_info);
      
      let ret = nt_create_user_process(
        process_handle,  // NULL
        thread_handle,  // NULL
        (0x000F0000) |  (0x00100000) | 0xFFFF, //PROCESS_ALL_ACCESS
        (0x000F0000) |  (0x00100000) | 0xFFFF, //THREAD_ALL_ACCESS
        ptr::null_mut(), 
        ptr::null_mut(), 
        0x00000004, //PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT
        0, 
        ptr::null_mut(), 
        ps_create_info, // Default PS_CREATE_INFO struct
        ptr::null_mut()
        );

      ret
   }

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
///     if addr != 0
///     {
///         println!("The function with ordinal 8 is located at 0x{:X}.", addr);
///     }
/// }
/// ```
pub fn ldr_get_procedure_address (module_handle: usize, function_name: &str, ordinal: u32) -> usize {

    unsafe 
    {   
        let ret: Option<i32>;
        let func_ptr: data::LdrGetProcedureAddress;
        let hmodule: PVOID = std::mem::transmute(module_handle);
        let r = usize::default();
        let return_address: *mut c_void = std::mem::transmute(&r);
        let return_address: *mut PVOID = std::mem::transmute(return_address);
        let f: UnsafeCell<String> = String::default().into();
        let mut fun_name: *mut String = std::mem::transmute(f.get());

        if function_name == ""
        {
            fun_name = ptr::null_mut();
        }
        else 
        {
            *fun_name = function_name.to_string();
        }

        let module_base_address = get_module_base_address(&lc!("ntdll.dll")); 
        dynamic_invoke!(module_base_address,&lc!("LdrGetProcedureAddress"),func_ptr,ret,hmodule,fun_name,ordinal,return_address);

        match ret {
            Some(x) => 
            {
                if x == 0
                {
                    return *return_address as usize;
                } 
                else 
                {
                    return 0;
                }
            },
            None => return 0,
        }
    }
}

/// Dynamically calls SetUnhandledExceptionFilter.
pub fn set_unhandled_exception_filter(address: usize) -> LptopLevelExceptionFilter
{
    unsafe 
    {
        let ret: Option<LptopLevelExceptionFilter>;
        let func_ptr: data::SetUnhandledExceptionFilter;
        let module_base_address = get_module_base_address(&lc!("kernel32.dll")); 
        dynamic_invoke!(module_base_address,&lc!("SetUnhandledExceptionFilter"),func_ptr,ret,address);

        match ret {
            Some(x) => return x,
            None => return 0,
        }
    }
}

/// Dynamically calls AddVectoredExceptionHandler.
pub fn add_vectored_exception_handler(first: u32, address: usize) -> PVOID
{
    unsafe 
    {
        let ret: Option<PVOID>;
        let func_ptr: data::AddVectoredExceptionHandler;
        let module_base_address = get_module_base_address(&lc!("kernel32.dll")); 
        dynamic_invoke!(module_base_address,&lc!("AddVectoredExceptionHandler"),func_ptr,ret,first,address);

        match ret {
            Some(x) => return x,
            None => return ptr::null_mut(),
        }
    }
}

/// Uses the Thread Pool to call LoadLibraryA.
///
/// It will return either the module's base address or 0.
///
/// # Examples
///
/// ```
/// let ret = dinvoke::load_library_a_tp("ntdll.dll");
///
/// if ret != 0 {println!("ntdll.dll base address is 0x{:X}.", addr)};
/// ```
pub fn load_library_a_tp(module: &str) -> usize {

    unsafe 
    {   
        let ret: Option<i32>;
        let func_ptr: data::RtlQueueWorkItem;
        let name = CString::new(module.to_string()).expect("");
        let module_name: PVOID = std::mem::transmute(name.as_ptr());
        let k32 = get_module_base_address(&lc!("kernel32.dll")); 
        let ntdll = get_module_base_address(&lc!("ntdll.dll")); 
        let load_library = get_function_address(k32, &lc!("LoadLibraryA"));
        dynamic_invoke!(ntdll,&lc!("RtlQueueWorkItem"),func_ptr,ret,load_library,module_name,0);


        match ret
        {
            Some(x) => 
            {
                if x != 0
                {
                    return 0;
                }
                else 
                {
                    use std::{thread, time};
                    let ten_millis = time::Duration::from_millis(500);
                    thread::sleep(ten_millis);
            
                    return get_module_base_address(module);
                }
            },
            None => { return 0; }
        }
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
/// if ret != 0 {println!("ntdll.dll base address is 0x{:X}.", addr)};
/// ```
pub fn load_library_a(module: &str) -> usize {

    unsafe 
    {   
        let ret: Option<usize>;
        let func_ptr: data::LoadLibraryA;
        let name = CString::new(module.to_string()).expect("");
        let module_name: *mut u8 = std::mem::transmute(name.as_ptr());
        let k32 = get_module_base_address(&lc!("kernel32.dll")); 
        dynamic_invoke!(k32,&lc!("LoadLibraryA"),func_ptr,ret,module_name);

        match ret
        {
            Some(x) => { return x; },
            None => { return 0; }
        }
    }     
}

/// Frees the loaded dll. The function expects the module's base address.
///
/// If the function succeeds, the return value is nonzero.
///
/// # Examples
///
/// ```
/// let module_handle: usize = dinvoke::load_library_a("somedll.dll");
/// let ret = dinvoke::free_library(module_handle as isize);
///
/// if ret == 0 {println!("somedll.dll sucessfully freed.")};
/// ```
pub fn free_library(module_handle: isize) -> usize {

    unsafe 
    {   
        let ret: Option<HINSTANCE>;
        let func_ptr: data::FreeLibrary;
        let module_base_address = get_module_base_address(&lc!("kernel32.dll")); 
        dynamic_invoke!(module_base_address,&lc!("FreeLibrary"),func_ptr,ret,module_handle);

        match ret {
            Some(x) => return x.0 as usize,
            None => return 0,
        }
    }     
}

/// Dynamically calls CreateFileA.
/// On success, it returns a valid handle to the specified file. Otherwise, a null handle is returned.
pub fn create_file_a(name: *mut u8, access: u32, mode: u32, attributes: *const SECURITY_ATTRIBUTES, disposition: u32, flags: u32, template: HANDLE) -> HANDLE {
    
    unsafe 
    {
        let ret: Option<HANDLE>;
        let func_ptr: data::CreateFileA;
        let kernel32 = get_module_base_address(&lc!("kernel32.dll"));
        dynamic_invoke!(kernel32,&lc!("CreateFileA"),func_ptr,ret,name,access,mode,attributes,disposition,flags,template);

        match ret {
            Some(x) => return x,
            None => return HANDLE { 0: 0 } ,
        }
    }   
}

/// Dynamically calls GetFileSize.
/// It returns either the specified file size (success) or 0 (an error ocurred).
pub fn get_file_size(handle: HANDLE, size: *mut u32) -> u32 {
    
    unsafe 
    {
        let ret: Option<u32>;
        let func_ptr: data::GetFileSize;
        let kernel32 = get_module_base_address(&lc!("kernel32.dll"));
        dynamic_invoke!(kernel32,&lc!("GetFileSize"),func_ptr,ret,handle,size);

        match ret {
            Some(x) => return x,
            None => return 0,
        }
    }   
}

/// Dynamically calls CreateFileMappingW.
///
pub fn create_file_mapping_w(file: HANDLE, attributes: *const SECURITY_ATTRIBUTES, protect: u32, max_size_high: u32, max_size_low: u32, name: *mut u8) -> HANDLE {
    
    unsafe 
    {
        let ret: Option<HANDLE>;
        let func_ptr: data::CreateFileMapping;
        let kernel32 = get_module_base_address(&lc!("kernel32.dll"));
        dynamic_invoke!(kernel32,&lc!("CreateFileMappingW"),func_ptr,ret,file,attributes,protect,max_size_high,max_size_low,name);

        match ret {
            Some(x) => return x,
            None => return HANDLE { 0: 0 } ,
        }
    }   
}

/// Dynamically calls MapViewOfFile.
///
pub fn map_view_of_file (file: HANDLE, access: u32, off_high: u32, off_low: u32, bytes: usize) -> PVOID {
    
    unsafe 
    {
        let ret: Option<PVOID>;
        let func_ptr: data::MapViewOfFile;
        let kernel32 = get_module_base_address(&lc!("kernel32.dll"));
        dynamic_invoke!(kernel32,&lc!("MapViewOfFile"),func_ptr,ret,file,access,off_high,off_low,bytes);

        match ret {
            Some(x) => return x,
            None => return ptr::null_mut() ,
        }
    }   
}

/// Dynamically calls UnmapViewOfFile.
///
pub fn unmap_view_of_file (base_address: PVOID) -> bool {
    
    unsafe 
    {
        let ret: Option<BOOL>;
        let func_ptr: data::UnmapViewOfFile;
        let kernel32 = get_module_base_address(&lc!("kernel32.dll"));
        dynamic_invoke!(kernel32,&lc!("UnmapViewOfFile"),func_ptr,ret,base_address);

        match ret {
            Some(x) => return x.as_bool(),
            None => return false ,
        }
    }   
}

/// Dynamically calls RollbackTransaction.
///
pub fn rollback_transaction(transaction: HANDLE) -> bool {
    
    unsafe 
    {
        let ret: Option<BOOL>;
        let func_ptr: data::RollbackTransaction;
        let ktmv = load_library_a(&lc!("KtmW32.dll"));
        dynamic_invoke!(ktmv,&lc!("RollbackTransaction"),func_ptr,ret,transaction);

        match ret {
            Some(x) => return x.as_bool(),
            None => return false ,
        }
    }   
}

/// Opens a HANDLE to a process.
///
/// If the function fails, it will return a null HANDLE.
///
/// # Examples
///
/// ```
/// let pid = 792u32;
/// let handle = dinvoke::open_process(0x0040, 0, pid); //PROCESS_DUP_HANDLE access right.
/// 
/// if handle.0 != 0
/// {
///     println!("Handle to process with id {} with PROCESS_DUP_HANDLE access right successfully obtained.", pid);
/// }
/// ```
pub fn open_process(desired_access: u32, inherit_handle: i32, process_id: u32) -> HANDLE {

    unsafe 
    {    
        let ret: Option<HANDLE>;
        let func_ptr: data::OpenProcess;
        let module_base_address = get_module_base_address(&lc!("kernel32.dll")); 
        dynamic_invoke!(module_base_address,&lc!("OpenProcess"),func_ptr,ret,desired_access,inherit_handle,process_id);

        match ret {
            Some(x) => return x,
            None => return HANDLE::default(),
        }
    }

}

/// Opens a HANDLE to a thread.
///
/// If the function fails, it will return a null HANDLE.
///
/// # Examples
///
/// ```
/// let thread_id = 792u32;
/// let handle = dinvoke::open_thread(0x0002, 0, pid); //THREAD_SUSPEND_RESUME access right.
/// 
/// if handle.0 != 0
/// {
///     println!("Handle to thread with id {} with THREAD_SUSPEND_RESUME access right successfully obtained.", thread_id);
/// }
/// ```
pub fn open_thread(desired_access: u32, inherit_handle: i32, thread_id: u32) -> HANDLE {

    unsafe 
    {    
        let ret: Option<HANDLE>;
        let func_ptr: data::OpenThread;
        let module_base_address = get_module_base_address(&lc!("kernel32.dll")); 
        dynamic_invoke!(module_base_address,&lc!("OpenThread"),func_ptr,ret,desired_access,inherit_handle,thread_id);

        match ret {
            Some(x) => return x,
            None => return HANDLE::default(),
        }
    }

}

/// Closes a HANDLE object.
///
/// It will return either a boolean value or an Err with a descriptive error message. If the function
/// fails the bool value returned will be false.
///
/// # Examples
///
/// ```
/// let pid = 792u32;
/// let handle = dinvoke::open_process(0x0040, 0, pid); //PROCESS_DUP_HANDLE access right.
/// 
/// if handle.0 != 0 && handle.0 != -1
/// {
///     let r = dinvoke::close_handle(handle);
///     if r
///     {
///         println!("Handle to process with id {} closed.", pid);
///     }
/// }
/// ```
pub fn close_handle(handle: HANDLE) -> bool {
    unsafe 
    {
        let ret: Option<i32>;
        let func_ptr: data::CloseHandle;
        let ntdll = get_module_base_address(&lc!("kernel32.dll"));
        dynamic_invoke!(ntdll,&lc!("CloseHandle"),func_ptr,ret,handle);

        match ret {
            Some(x) =>
            {
                if x == 0
                {
                    return false;
                }
                else 
                {
                    return true;
                }
            },
            None => return false,
        }
    }
}

/// Dynamically calls TlsAlloc.
pub fn tls_alloc() -> u32
{
    unsafe 
    {    
        let ret: Option<u32>;
        let func_ptr: data::TlsAlloc;
        let module_base_address = get_module_base_address(&lc!("kernel32.dll")); 
        dynamic_invoke!(module_base_address,&lc!("TlsAlloc"),func_ptr,ret,);

        match ret {
            Some(x) => return x,
            None => return TLS_OUT_OF_INDEXES, 
        }
    }
}

/// Dynamically calls TlsGetValue.
pub fn tls_get_value(index: u32) -> PVOID
{
    unsafe 
    {    
        let ret: Option<PVOID>;
        let func_ptr: data::TlsGetValue;
        let module_base_address = get_module_base_address(&lc!("kernel32.dll")); 
        dynamic_invoke!(module_base_address,&lc!("TlsGetValue"),func_ptr,ret,index);

        match ret {
            Some(x) => return x,
            None => return ptr::null_mut(), 
        }
    }
}

/// Dynamically calls TlsSetValue.
pub fn tls_set_value(index: u32, data: PVOID) -> bool
{
    unsafe 
    {    
        let ret: Option<bool>;
        let func_ptr: data::TlsSetValue;
        let module_base_address = get_module_base_address(&lc!("kernel32.dll")); 
        dynamic_invoke!(module_base_address,&lc!("TlsSetValue"),func_ptr,ret,index,data);

        match ret {
            Some(x) => return x,
            None => return false, 
        }
    }
}

/// Dynamically calls EnumProcessModules.
pub fn enum_process_modules(process: HANDLE, module: *mut usize, cb: u32, needed: *mut u32) -> bool
{
    unsafe 
    {    
        let ret: Option<bool>;
        let func_ptr: data::EnumProcessModules;
        let module_base_address = get_module_base_address(&lc!("kernel32.dll")); 
        dynamic_invoke!(module_base_address,&lc!("EnumProcessModules"),func_ptr,ret,process,module,cb,needed);

        match ret {
            Some(x) => return x,
            None => return false, 
        }
    }
}

/// Dynamically calls GetModuleHandleExA.
pub fn get_module_handle_ex_a(flags: i32, module_name: *const u8, module: *mut usize) -> bool
{
    unsafe 
    {    
        let ret: Option<bool>;
        let func_ptr: data::GetModuleHandleExA;
        let module_base_address = get_module_base_address(&lc!("kernel32.dll")); 
        dynamic_invoke!(module_base_address,&lc!("GetModuleHandleExA"),func_ptr,ret,flags,module_name,module);

        match ret {
            Some(x) => return x,
            None => return false, 
        }
    }
}

/// Dynamically calls GetModuleBaseNameW.
pub fn get_module_base_name_w(process: HANDLE, module: usize, base_name: *mut u16, size: u32) -> u32
{
    unsafe 
    {    
        let ret: Option<u32>;
        let func_ptr: data::GetModuleBaseNameW;
        let module_base_address = get_module_base_address(&lc!("kernel32.dll")); 
        dynamic_invoke!(module_base_address,&lc!("GetModuleBaseNameW"),func_ptr,ret,process,module,base_name,size);

        match ret {
            Some(x) => return x,
            None => return 0, 
        }
    }
}

/// Dynamically calls GetModuleBaseNameW.
pub fn get_module_file_name_ex_w(process: HANDLE, module: usize, base_name: *mut u16, size: u32) -> u32
{
    unsafe 
    {    
        let ret: Option<u32>;
        let func_ptr: data::GetModuleFileNameExW;
        let module_base_address = get_module_base_address(&lc!("kernel32.dll")); 
        dynamic_invoke!(module_base_address,&lc!("GetModuleFileNameExW"),func_ptr,ret,process,module,base_name,size);

        match ret {
            Some(x) => return x,
            None => return 0, 
        }
    }
}

/// Dynamically calls GetLastError.
pub fn get_last_error() -> u32
{
    unsafe 
    {    
        let ret: Option<u32>;
        let func_ptr: data::GetLastError;
        let module_base_address = get_module_base_address(&lc!("kernel32.dll")); 
        dynamic_invoke!(module_base_address,&lc!("GetLastError"),func_ptr,ret,);

        match ret {
            Some(x) => return x,
            None => return 0xf, 
        }
    }
}

/// Dynamically calls LocalAlloc.
pub fn local_alloc(flags: u32, size: usize) -> PVOID
{
    unsafe 
    {    
        let ret: Option<PVOID>;
        let func_ptr: data::LocalAlloc;
        let module_base_address = get_module_base_address(&lc!("kernel32.dll")); 
        dynamic_invoke!(module_base_address,&lc!("localAlloc"),func_ptr,ret,flags,size);

        match ret {
            Some(x) => return x,
            None => return ptr::null_mut(), 
        }
    }
}

/// Dynamically calls GetSystemInfo.
pub fn get_system_info(sysinfo: *mut SYSTEM_INFO)  {
    
    unsafe 
    {
        let _ret: Option<()>;
        let func_ptr: data::GetSystemInfo;
        let kernel32 = get_module_base_address(&lc!("kernel32.dll"));
        dynamic_invoke!(kernel32,&lc!("GetSystemInfo"),func_ptr,_ret,sysinfo);
    }   
}

/// Dynamically calls VirtualQueryEx.
pub fn virtual_query_ex(process_handle: HANDLE, page_address: *const c_void, buffer: *mut MEMORY_BASIC_INFORMATION, length: usize)  -> usize{
    
    unsafe 
    {
        let ret: Option<usize>;
        let func_ptr: data::VirtualQueryEx;
        let kernel32 = get_module_base_address(&lc!("kernel32.dll"));
        dynamic_invoke!(kernel32,&lc!("VirtualQueryEx"),func_ptr,ret,process_handle,page_address,buffer,length);

        match ret {
            Some(x) => return x,
            None => return 0 ,
        }
    }   
}

/// Dynamically calls VirtualFree.
pub fn virtual_free(address: PVOID, size: usize, free_type: u32) -> bool {
    unsafe 
    {
        let ret: Option<bool>;
        let func_ptr: data::VirtualFree;
        let k32 = get_module_base_address(&lc!("kernel32.dll"));
        dynamic_invoke!(k32,&lc!("VirtualFree"),func_ptr,ret,address,size,free_type);

        match ret {
            Some(x) =>
            {
                return x;
            },
            None => return false,
        }
    }
}

/// Dynamically calls NtCreateUserProcess.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_create_user_process(process_handle: *mut HANDLE, thread_handle: *mut HANDLE, process_access: u32, thread_access: u32, object_attributes: *mut OBJECT_ATTRIBUTES,
    thread_object_attr: *mut OBJECT_ATTRIBUTES, process_flags: u32, thread_flags: u32, parameters: PVOID, create_info: *mut PsCreateInfo, attr_list: *mut PsAttributeList) -> i32 {
    
    unsafe 
    {
        let ret: Option<i32>;
        let func_ptr: data::NtCreateUserProcess;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("NtCreateUserProcess"),func_ptr,ret,process_handle,thread_handle,process_access,thread_access,object_attributes,thread_object_attr,
                        process_flags,thread_flags,parameters,create_info,attr_list);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    } 
}

/// Dynamically calls NtWriteVirtualMemory.
///
/// It will return the NTSTATUS value returned by the call.
#[cfg(target_arch = "x86_64")]
pub fn nt_write_virtual_memory (mut handle: HANDLE, base_address: PVOID, mut buffer: PVOID, mut size: usize, bytes_written: *mut usize) -> i32 {

    unsafe 
    {
        let ret;
        let func_ptr: data::NtWriteVirtualMemory;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));

        if HARDWARE_BREAKPOINTS
        {
            let addr = get_function_address(ntdll, &lc!("NtWriteVirtualMemory")) as usize;
            HARDWARE_EXCEPTION_FUNCTION =  ExceptionHandleFunction::NtWriteVirtualMemory;
            NT_WRITE_VIRTUAL_MEMORY_ARGS.handle = handle;
            NT_WRITE_VIRTUAL_MEMORY_ARGS.base_address = base_address;
            NT_WRITE_VIRTUAL_MEMORY_ARGS.buffer = buffer;
            NT_WRITE_VIRTUAL_MEMORY_ARGS.size = size;
            set_hardware_breakpoint(find_syscall_address(addr));

            handle = HANDLE {0: -1};
            let buff = vec![20];
            buffer = std::mem::transmute(buff.as_ptr());
            size = buff.len();
        }

        dynamic_invoke!(ntdll,&lc!("NtWriteVirtualMemory"),func_ptr,ret,handle,base_address,buffer,size,bytes_written);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    }

}

/// Dynamically calls NtWriteVirtualMemory.
///
/// It will return the NTSTATUS value returned by the call.
#[cfg(target_arch = "x86")]
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

/// Dynamically calls NtAllocateVirtualMemory.
///
/// It will return the NTSTATUS value returned by the call.
#[cfg(target_arch = "x86_64")]
pub fn nt_allocate_virtual_memory (mut handle: HANDLE, mut base_address: *mut PVOID, zero_bits: usize, size: *mut usize, allocation_type: u32, protection: u32) -> i32 {

    unsafe 
    {
        let ret;
        let func_ptr: data::NtAllocateVirtualMemory;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        
        if HARDWARE_BREAKPOINTS
        {
            let addr = get_function_address(ntdll, &lc!("NtAllocateVirtualMemory")) as usize;
            HARDWARE_EXCEPTION_FUNCTION = ExceptionHandleFunction::NtAllocateVirtualMemory;
            NT_ALLOCATE_VIRTUAL_MEMORY_ARGS.handle = handle;
            NT_ALLOCATE_VIRTUAL_MEMORY_ARGS.base_address = base_address;
            set_hardware_breakpoint(find_syscall_address(addr));

            handle = HANDLE {0: -1};
            base_address = ptr::null_mut();
        }
        
        dynamic_invoke!(ntdll,&lc!("NtAllocateVirtualMemory"),func_ptr,ret,handle,base_address,zero_bits,size,allocation_type,protection);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    }   
}

/// Dynamically calls NtAllocateVirtualMemory.
///
/// It will return the NTSTATUS value returned by the call.
#[cfg(target_arch = "x86")]
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

/// Dynamically calls NtProtectVirtualMemory.
///
/// It will return the NTSTATUS value returned by the call.
#[cfg(target_arch = "x86_64")]
pub fn nt_protect_virtual_memory (mut handle: HANDLE, mut base_address: *mut PVOID, mut size: *mut usize, mut new_protection: u32, old_protection: *mut u32) -> i32 {
    
    unsafe 
    {
        let ret;
        let func_ptr: data::NtProtectVirtualMemory;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));

        if HARDWARE_BREAKPOINTS
        {
            let addr = get_function_address(ntdll, &lc!("NtProtectVirtualMemory")) as usize;
            HARDWARE_EXCEPTION_FUNCTION =  ExceptionHandleFunction::NtProtectVirtualMemory;
            NT_PROTECT_VIRTUAL_MEMORY_ARGS.handle = handle;
            NT_PROTECT_VIRTUAL_MEMORY_ARGS.base_address = base_address;
            NT_PROTECT_VIRTUAL_MEMORY_ARGS.size = size;
            NT_PROTECT_VIRTUAL_MEMORY_ARGS.protection = new_protection;
            set_hardware_breakpoint(find_syscall_address(addr));

            handle = HANDLE {0: -1};
            base_address = ptr::null_mut();
            let s = 10usize;
            size = std::mem::transmute(&s);
            new_protection = PAGE_READONLY;
        }

        dynamic_invoke!(ntdll,&lc!("NtProtectVirtualMemory"),func_ptr,ret,handle,base_address,size,new_protection,old_protection);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    } 
}

/// Dynamically calls NtProtectVirtualMemory.
///
/// It will return the NTSTATUS value returned by the call.
#[cfg(target_arch = "x86")]
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

/// Dynamically calls NtOpenProcess.
///
/// It will return the NTSTATUS value returned by the call.
#[cfg(target_arch = "x86_64")]
pub fn nt_open_process (mut handle: *mut HANDLE, mut access: u32, mut attributes: *mut OBJECT_ATTRIBUTES, mut client_id: *mut ClientId) -> i32 {
    
    unsafe 
    {
        let ret;
        let func_ptr: data::NtOpenProcess;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));

        if HARDWARE_BREAKPOINTS
        {
            let addr = get_function_address(ntdll, &lc!("NtOpenProcess")) as usize;
            HARDWARE_EXCEPTION_FUNCTION =  ExceptionHandleFunction::NtOpenProcess;
            NT_OPEN_PROCESS_ARGS.handle = handle;
            NT_OPEN_PROCESS_ARGS.access = access;
            NT_OPEN_PROCESS_ARGS.attributes = attributes;
            NT_OPEN_PROCESS_ARGS.client_id = client_id;
            set_hardware_breakpoint(find_syscall_address(addr));

            let h = HANDLE {0: -1};
            handle = std::mem::transmute(&h);
            access = PROCESS_QUERY_LIMITED_INFORMATION; 
            let a = OBJECT_ATTRIBUTES::default();
            attributes = std::mem::transmute(&a);
            let c = ClientId {unique_process: HANDLE {0: std::process::id() as isize}, unique_thread: HANDLE::default()};
            client_id = std::mem::transmute(&c);
        }

        dynamic_invoke!(ntdll,&lc!("NtOpenProcess"),func_ptr,ret,handle,access,attributes,client_id);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    } 
}

/// Dynamically calls NtOpenProcess.
///
/// It will return the NTSTATUS value returned by the call.
#[cfg(target_arch = "x86")]
pub fn nt_open_process (handle: *mut HANDLE, access: u32, attributes: *mut OBJECT_ATTRIBUTES, client_id: *mut ClientId) -> i32 {
    
    unsafe 
    {
        let ret;
        let func_ptr: data::NtOpenProcess;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("NtOpenProcess"),func_ptr,ret,handle,access,attributes,client_id);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    } 
}

/// Dynamically calls NtQueryInformationProcess.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_query_information_process (handle: HANDLE, process_information_class: u32, process_information: PVOID, length: u32, return_length: *mut u32) -> i32 {
    
    unsafe 
    {
        let ret;
        let func_ptr: data::NtQueryInformationProcess;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("NtQueryInformationProcess"),func_ptr,ret,handle,process_information_class,process_information,length,return_length);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    } 
}

/// Dynamically calls NtQueryInformationThread.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_query_information_thread (handle: HANDLE, thread_information_class: u32, thread_information: PVOID, length: u32, return_length: *mut u32) -> i32 {
    
    unsafe 
    {
        let ret;
        let func_ptr: data::NtQueryInformationThread;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("NtQueryInformationThread"),func_ptr,ret,handle,thread_information_class,thread_information,length,return_length);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    } 
}

/// Dynamically calls NtQueryInformationFile.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_query_information_file(handle: HANDLE, io: *mut IO_STATUS_BLOCK, file_information: PVOID, length: u32,file_information_class: u32) -> i32 {
    
    unsafe 
    {
        let ret;
        let func_ptr: data::NtQueryInformationFile;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("NtQueryInformationFile"),func_ptr,ret,handle,io,file_information,length,file_information_class);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    } 
}

/// Dynamically calls RtlAdjustPrivilege.
///
/// It will return the NTSTATUS value returned by the call.
pub fn rtl_adjust_privilege(privilege: u32, enable: u8, current_thread: u8, enabled: *mut u8) -> i32 {
    
    unsafe 
    {
        let ret;
        let func_ptr: data::RtlAdjustPrivilege;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("RtlAdjustPrivilege"),func_ptr,ret,privilege,enable,current_thread,enabled);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    } 
}

/// Dynamically calls RtlInitUnicodeString.
///
/// It will return the NTSTATUS value returned by the call.
pub fn rtl_init_unicode_string (destination_string: *mut UNICODE_STRING, source_string: *const u16) -> () 
{
    unsafe
    {
        let _ret: Option<()>;
        let func_ptr: data::RtlInitUnicodeString;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("RtlInitUnicodeString"),func_ptr,_ret,destination_string, source_string);
    }
}

/// Dynamically calls RtlZeroMemory.
///
/// It will return the NTSTATUS value returned by the call.
pub fn rtl_zero_memory (address: PVOID, length: usize) -> () 
{
    unsafe
    {
        let _ret: Option<()>;
        let func_ptr: data::RtlZeroMemory;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("RtlZeroMemory"),func_ptr,_ret,address,length);
    }
}

/// Dynamically calls NtOpenFile.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_open_file (file_handle: *mut HANDLE, desired_access: u32, object_attributes: *mut OBJECT_ATTRIBUTES, 
                     io: *mut IO_STATUS_BLOCK, share_access: u32, options: u32) -> i32
{
    unsafe 
    {
        let ret: Option<i32>;
        let func_ptr: data::NtOpenFile;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("NtOpenFile"),func_ptr,ret,file_handle,desired_access,object_attributes,io,share_access,options);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    } 
}

/// Dynamically calls NtCreateSection.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_create_section (section_handle: *mut HANDLE, desired_access: u32, object_attributes: *mut OBJECT_ATTRIBUTES, 
                          size: *mut LARGE_INTEGER, page_protection: u32, allocation_attributes: u32, file_handle: HANDLE) -> i32
{
    unsafe 
    {
        let ret: Option<i32>;
        let func_ptr: data::NtCreateSection;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("NtCreateSection"),func_ptr,ret,section_handle,desired_access,
                        object_attributes,size,page_protection,allocation_attributes,file_handle);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    }
}

/// Dynamically calls NtMapViewOfSection.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_map_view_of_section (section_handle: HANDLE, process_handle: HANDLE, base_address: *mut PVOID, zero: usize, commit_size: usize, 
                               offset: *mut LARGE_INTEGER, view_size: *mut usize, disposition: u32, allocation_type: u32, protection: u32) -> i32
{
    unsafe 
    {
        let ret: Option<i32>;
        let func_ptr: data::NtMapViewOfSection;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("NtMapViewOfSection"),func_ptr,ret,section_handle,process_handle,base_address,zero,commit_size,
                        offset,view_size,disposition,allocation_type,protection);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    }
}

/// Dynamically calls NtCreateThreadEx.
///
/// It will return the NTSTATUS value returned by the call.
#[cfg(target_arch = "x86_64")]
pub fn nt_create_thread_ex (mut thread: *mut HANDLE, mut access: u32, mut attributes: *mut OBJECT_ATTRIBUTES, mut process: HANDLE, function: PVOID, 
    args: PVOID, flags: u32, zero: usize, stack: usize, reserve: usize, buffer: *mut PsAttributeList) -> i32
{
    unsafe 
    {
        let ret: Option<i32>;
        let func_ptr: data::NtCreateThreadEx;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));

        if HARDWARE_BREAKPOINTS
        {
            let addr = get_function_address(ntdll, "NtCreateThreadEx") as usize;
            HARDWARE_EXCEPTION_FUNCTION =  ExceptionHandleFunction::NtCreateThreadEx;
            NT_CREATE_THREAD_EX_ARGS.thread = thread;
            NT_CREATE_THREAD_EX_ARGS.access = access;
            NT_CREATE_THREAD_EX_ARGS.attributes = attributes;
            NT_CREATE_THREAD_EX_ARGS.process = process;
            set_hardware_breakpoint(find_syscall_address(addr));

            let h = HANDLE {0: -1};
            thread = std::mem::transmute(&h);
            access = PROCESS_QUERY_LIMITED_INFORMATION; 
            let a = OBJECT_ATTRIBUTES::default();
            attributes = std::mem::transmute(&a);
            process = HANDLE {0: -1};
        }

        dynamic_invoke!(ntdll,&lc!("NtCreateThreadEx"),func_ptr,ret,thread,access,attributes,process,function,args,flags,zero,stack,reserve,buffer);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    }
}

/// Dynamically calls NtCreateThreadEx.
///
/// It will return the NTSTATUS value returned by the call.
#[cfg(target_arch = "x86")]
pub fn nt_create_thread_ex (thread: *mut HANDLE, access: u32, attributes: *mut OBJECT_ATTRIBUTES, process: HANDLE, function: PVOID, 
    args: PVOID, flags: u32, zero: usize, stack: usize, reserve: usize, buffer: *mut PsAttributeList) -> i32
{
    unsafe 
    {
        let ret: Option<i32>;
        let func_ptr: data::NtCreateThreadEx;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("NtCreateThreadEx"),func_ptr,ret,thread,access,attributes,process,function,args,flags,zero,stack,reserve,buffer);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    }
}

/// Dynamically calls NtReadVirtualMemory.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_read_virtual_memory (handle: HANDLE, base_address: PVOID, buffer: PVOID, size: usize, bytes_written: *mut usize) -> i32 {

    unsafe 
    {
        let ret;
        let func_ptr: data::NtReadVirtualMemory;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("NtReadVirtualMemory"),func_ptr,ret,handle,base_address,buffer,size,bytes_written);
        
        match ret {
            Some(x) => return x,
            None => return -1,
        }
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
/// dinvoke::dynamic_invoke(&a.0, a.1, ret); // dinvoke::dynamic_invoke(&PeMetadata, usize, bool)
/// if ret { println!("Entry point successfully called.");}
/// ```
/// # Example - Dynamically calling LoadLibraryA
///
/// ```ignore
/// let kernel32 = manualmap::read_and_map_module("c:\\windows\\system32\\kernel32.dll").unwrap();
/// let mut ret:Option<HINSTANCE>;
/// let function_ptr: data::LoadLibraryA;
/// let name = CString::new("ntdll.dll").expect("CString::new failed");
/// let module_name = PSTR{0: name.as_ptr() as *mut u8};
/// //dinvoke::dynamic_invoke(usize,&str,<function_type>,Option<return_type>,[arguments])
/// dinvoke::dynamic_invoke(a.1, "LoadLibraryA", function_ptr, ret, module_name);
///
/// match ret {
///     Some(x) => if x.0 == 0 {println!("ntdll base address is 0x{:X}",x.0);},
///     None => println!("Error calling LdrGetProcedureAddress"),
/// }
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
/// let return_address: *mut c_void = std::mem::transmute(&usize::default());
/// let return_address: *mut PVOID = std::mem::transmute(return_address);
/// //dinvoke::dynamic_invoke(usize,&str,<function_type>,Option<return_type>,[arguments])
/// dinvoke::dynamic_invoke!(ptr,"LdrGetProcedureAddress",function_ptr,ret,hmodule,fun_name,ordinal,return_address);
///
/// match ret {
///     Some(x) => if x == 0 {println!("RtlDispatchAPC is located at the address: 0x{:X}",*return_address as usize);},
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

/// Dynamically execute an indirect syscall.
///
/// This function expects as parameters the name of the Nt function whose syscall 
/// wants to be executed, a variable with the function header, an Option variable with the same
/// inner type that the original syscall would return and all the parameters expected by the syscall.
///
/// # Examples - Executing NtQueryInformationProcess with indirect syscall
///
/// ```ignore      
/// let function_type:NtQueryInformationProcess;
/// let mut ret: Option<i32> = None; //NtQueryInformationProcess returns a NTSTATUS, which is a i32.
/// let handle = GetCurrentProcess();
/// let p = PROCESS_BASIC_INFORMATION::default();
/// let process_information: *mut c_void = std::mem::transmute(&pi); 
/// let r = u32::default();
/// let return_length: *mut u32 = std::mem::transmute(&r);
/// dinvoke::execute_syscall!(
///     "NtQueryInformationProcess",
///     function_type,
///     ret,
///     handle,
///     0,
///     process_information,
///     size_of::<PROCESS_BASIC_INFORMATION>() as u32,
///     return_length
/// );
/// match ret {
///     Some(x) => if x == 0 {println!("Process information struct available at address 0x{:X}",process_information as usize);},
///     None => println!("Error executing direct syscall for NtQueryInformationProcess."),
/// }
/// ```
#[cfg(target_arch = "x86_64")]
#[macro_export]
macro_rules! execute_syscall {

    ($a:expr, $b:expr, $c:expr, $($d:tt)*) => {

        let eat = $crate::get_ntdll_eat($crate::get_module_base_address("ntdll.dll"));
        let id = $crate::get_syscall_id(&eat, $a);
        if id != u32::MAX
        {
            let function_ptr = $crate::prepare_syscall(id as u32, eat);
            if function_ptr != 0
            {
                $b = std::mem::transmute(function_ptr);
                $c = Some($b($($d)*));
            }
            else
            {
                $c = None;
            }
            let ptr = std::mem::transmute(function_ptr);
            $crate::virtual_free(ptr, 0, 0x00008000);
        }
        else
        {
            $c = None;
        }
    }
}
