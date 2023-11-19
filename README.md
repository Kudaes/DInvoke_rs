# DInvoke_rs

Rust port of [Dinvoke](https://github.com/TheWover/DInvoke). DInvoke_rs may be used for many purposes such as PE parsing, dynamic exported functions resolution, dynamically loading PE plugins at runtime, API hooks evasion and more. This project is meant to be used as a template (just add your own Rust code on top of it) or as a nested crate that can be imported on your own project.

Features:
* Dynamically resolve and invoke undocumented Windows APIs from Rust.
* Primitives allowing for strategic API hook evasion. 
* Indirect syscalls. **x64 only**
* Manually map PE modules from disk or directly from memory.
* PE headers parsing.
* Map PE modules into sections backed by arbitrary modules on disk. **Not Opsec**
* Module fluctuation to hide mapped PEs (concurrency supported). **Not Opsec**
* Syscall parameters spoofing through exception filter + hardware breakpoints. **x64 only**

# Credit
All the credits go to the creators of the original C# implementation of this tool:
* [The Wover](https://twitter.com/TheRealWover)
* [FuzzySec (b33f)](https://twitter.com/FuzzySec)
* [cobbr](https://twitter.com/cobbr_io)

# Content

- [Resolve exported function](#Resolving-Exported-APIs)
- [Dynamically invoke unmanaged code](#Invoking-Unmanaged-Code)
- [Execute Indirect Syscall](#Executing-indirect-syscall)
- [Manually map a PE from disk or memory](#Manual-PE-mapping)
- [Overload memory section](#Overload-memory-section)
- [Module fluctuation](#Module-fluctuation)
- [Use hardware breakpoints to spoof syscall parameters](#Syscall-parameters-spoofing)

# Usage

Import this crate into your project by adding the following line to your `cargo.toml`:

```rust
[dependencies]
dinvoke_rs = "0.1.2"
```

# Examples
## Resolving Exported APIs

The example below demonstrates how to use DInvoke_rs to dynamically find and call exports of a DLL (ntdll.dll in this case).

1) Get ntdll's base address.
2) Use get_function_address() to find an export within ntdll.dll by name. This is done by walking and parsing the dll's EAT.
3) You can also find an export by ordinal by calling get_function_address_by_ordinal(). 

```rust

fn main() {

    // Dynamically obtain ntdll.dll's base address. 
    let ntdll = dinvoke::get_module_base_address("ntdll.dll");

    if ntdll != 0 
    {
        println!("ntdll.dll base address is 0x{:X}", ntdll);
        
        // Dynamically obtain the address of a function by name.
        let nt_create_thread = dinvoke::get_function_address(ntdll, "NtCreateThread");
        if nt_create_thread != 0
        {
            println!("NtCreateThread is at address 0x{:X}", nt_create_thread);
        }

        // Dynamically obtain the address of a function by ordinal.
        let ordinal_8 = dinvoke::get_function_address_by_ordinal(ntdll, 8);
        if ordinal_8 != 0 
        {
            println!("The function with ordinal 8 is at addresss 0x{:X}", ordinal_8);
        }
    }   
}

```

## Invoking Unmanaged Code
In the example below, we use DInvoke_rs to dynamically call RtlAdjustPrivilege in order to enable SeDebugPrivilege for the current process token. This kind of execution will bypass any API hooks present in Win32. Also, it won't create any entry on the final PE Import Address Table, making it harder to detect the PE's behaviour without executing it.

```rust

fn main() {

    // Dynamically obtain ntdll.dll's base address. 
    let ntdll = dinvoke::get_module_base_address("ntdll.dll");

    if ntdll != 0 
    {
        unsafe 
        {
            let func_ptr:  unsafe extern "system" fn (u32, u8, u8, *mut u8) -> i32; // Function header available at data::RtlAdjustPrivilege
            let ret: Option<i32>; // RtlAdjustPrivilege returns an NSTATUS value, which in Rust can be represented as an i32
            let privilege: u32 = 20; // This value matches with SeDebugPrivilege
            let enable: u8 = 1; // Enable the privilege
            let current_thread: u8 = 0; // Enable the privilege for the current process, not only for the current thread
            let e = u8::default(); // https://github.com/Kudaes/rust_tips_and_tricks/tree/main#transmute
            let enabled: *mut u8 = std::mem::transmute(&e); 
            dinvoke::dynamic_invoke!(ntdll,"RtlAdjustPrivilege",func_ptr,ret,privilege,enable,current_thread,enabled); 
    
            match ret {
                Some(x) => 
                	if x == 0 { println!("NTSTATUS == Success. Privilege enabled."); } 
                  	else { println!("[x] NTSTATUS == {:X}", x as u32); },
                None => panic!("[x] Error!"),
            }
        } 
    }   
}


```

## Executing indirect syscall
In the next example, we use DInvoke_rs to execute the syscall that corresponds to the function NtQueryInformationProcess. Since the macro dinvoke::execute_syscall!() dynamically allocates and executes the shellcode required to perform the desired syscall, all hooks present in ntdll.dll are bypassed. The memory allocated is release once the syscall returns, avoiding the permanent presence of memory pages with execution permission.

```rust

use std::mem::size_of;
use windows::Win32::System::Threading::{GetCurrentProcess, PROCESS_BASIC_INFORMATION};
use data::{NtQueryInformationProcess, PVOID};

fn main() {

    unsafe 
    {
        let function_type:NtQueryInformationProcess;
        let mut ret: Option<i32> = None; //NtQueryInformationProcess returns a NTSTATUS, which is a i32.
        let handle = GetCurrentProcess();
        let p = PROCESS_BASIC_INFORMATION::default();
        let process_information: PVOID = std::mem::transmute(&p); 
        let r = u32::default();
        let return_length: *mut u32 = std::mem::transmute(&r);
        dinvoke::execute_syscall!(
            "NtQueryInformationProcess",
            function_type,
            ret,
            handle,
            0,
            process_information,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            return_length
        );

        let pbi:*mut PROCESS_BASIC_INFORMATION;
        match ret {
            Some(x) => 
                if x == 0 {
                    pbi = std::mem::transmute(process_information);
                    let pbi = *pbi;
                    println!("The Process Environment Block base address is 0x{:X}", pbi.PebBaseAddress as u64);
                },
            None => println!("[x] Error executing direct syscall for NtQueryInformationProcess."),
        }  

    }
}

```

## Manual PE mapping
In this example, DInvoke_rs is used to manually map a fresh copy of ntdll.dll, without any EDR hooks. Then that fresh ntdll.dll copy can be used to execute any desired function. 

This manual map can also be executed from memory (use manually_map_module() in that case), allowing the perform the classic reflective dll injection.

```rust

use data::PeMetadata;

fn main() {

    unsafe 
    {

        let ntdll: (PeMetadata, isize) = manualmap::read_and_map_module("C:\\Windows\\System32\\ntdll.dll").unwrap();
        
        let func_ptr:  unsafe extern "system" fn (u32, u8, u8, *mut u8) -> i32; // Function header available at data::RtlAdjustPrivilege
        let ret: Option<i32>; // RtlAdjustPrivilege returns an NSTATUS value, which is an i32
        let privilege: u32 = 20; // This value matches with SeDebugPrivilege
        let enable: u8 = 1; // Enable the privilege
        let current_thread: u8 = 0; // Enable the privilege for the current process, not only for the current thread
        let e = u8::default();
        let enabled: *mut u8 = std::mem::transmute(&e); 
        dinvoke::dynamic_invoke!(ntdll.1,"RtlAdjustPrivilege",func_ptr,ret,privilege,enable,current_thread,enabled);

        match ret {
            Some(x) => 
                if x == 0 { println!("NTSTATUS == Success. Privilege enabled."); } 
                else { println!("[x] NTSTATUS == {:X}", x as u32); },
            None => panic!("[x] Error!"),
        }

    }
}

```

## Overload memory section
In the following sample, DInvoke_rs is used to create a file-backed memory section, overloading it afterwards by manually mapping a PE. The memory section will point to a legitimate file located in %WINDIR%\System32\ by default, but any other decoy module can be used.

This overload can also be executed mapping a PE from memory (as it is shown in the following example), allowing to perform the overload without writing the payload to disk.

```rust

use data::PeMetadata;

fn main() {

    unsafe 
    {

        let payload: Vec<u8> = your_download_function();

        // This will map your payload into a legitimate file-backed memory section.
        let overload: (PeMetadata, isize) = overload::overload_module(payload, "").unwrap();
        
        // Then any exported function of the mapped PE can be dynamically called.
        // Let's say we want to execute a function with header pub fn random_function(i32, i32) -> i32
        let func_ptr:  unsafe extern "Rust" fn (i32, i32) -> i32; // Function header
        let ret: Option<i32>; // The value that the called function will return
        let parameter1: i32 = 10;
        let parameter2: i32 = 20;
        dinvoke::dynamic_invoke!(overload.1,"random_function",func_ptr,ret,parameter1,parameter2);

        match ret {
            Some(x) => 
                println!("The function returned the value {}", x),
            None => panic!("[x] Error!"),
        }

    }
}

```

## Module fluctuation
DInvoke_rs allows to hide mapped PEs when they are not being used, making it harder for EDR memory inspection to detect the presence of a suspicious dll in your process. 

For example, lets say we want to map a fresh copy of ntdll.dll in order to evade EDR hooks. Since two ntdll.dll in the same process could be considered a suspicious behaviour, we can map ntdll and hide it whenever we are not using it. This is very similar to the shellcode fluctuation technique, althought in this scenario we can take advantage of the fact that we are mapping a PE into a legitimate file-backed memory section, so we can replace the ntdll's content for the original decoy module's content that the section is pointing to.

```rust

use dmanager::Manager;

fn main() {

    unsafe 
    {

        // The manager will take care of the hiding/remapping process and it can be used in multi-threading scenarios 
        let mut manager = Manager::new();

        // This will map ntdll.dll into a memory section pointing to cdp.dll. 
        // It will return the payload (ntdll) content, the decoy module (cdp) content and the payload base address.
        let overload: ((Vec<u8>, Vec<u8>), isize) = overload::managed_read_and_overload("c:\\windows\\system32\\ntdll.dll", "c:\\windows\\system32\\cdp.dll").unwrap();
        
        // This will allow the manager to start taking care of the module fluctuation process over this mapped PE.
        // Also, it will hide ntdll, replacing its content with the legitimate cdp.dll content.
        let _r = manager.new_module(overload.1 as i64, overload.0.0, overload.0.1);

        // Now, if we want to use our fresh ntdll copy, we just need to tell the manager to remap our payload into the memory section.
        let _ = manager.map_module(overload.1 as i64);

        // After ntdll has being remapped, we can dynamically call RtlAdjustPrivilege (or any other function) without worrying about EDR hooks.
        let func_ptr:  unsafe extern "system" fn (u32, u8, u8, *mut u8) -> i32; // Function header available at data::RtlAdjustPrivilege
        let ret: Option<i32>; // RtlAdjustPrivilege returns an NSTATUS value, which is an i32
        let privilege: u32 = 20; // This value matches with SeDebugPrivilege
        let enable: u8 = 1; // Enable the privilege
        let current_thread: u8 = 0; // Enable the privilege for the current process, not only for the current thread
        let e = u8::default();
        let enabled: *mut u8 = std::mem::transmute(&e); 
        dinvoke::dynamic_invoke!(overload.1,"RtlAdjustPrivilege",func_ptr,ret,privilege,enable,current_thread,enabled);

        match ret {
            Some(x) => 
                if x == 0 { println!("NTSTATUS == Success. Privilege enabled."); } 
                else { println!("[x] NTSTATUS == {:X}", x as u32); },
            None => panic!("[x] Error!"),
        }

        // Since we dont want to use our ntdll copy for the moment, we hide it again. It can we remapped at any time.
        let _ = manager.hide(overload.1 as i64);

    }
}

```

## Syscall parameters spoofing
In order to spoof the first 4 parameters of a syscall, DInvoke_rs has support for hardware breakpoints in combination with exception handlers. This allows to send not malicious parameters to a NT function, and after the EDR has inspected them, they are replaced by the original parameters before the syscall instruction is executed. For further information, check out the repository where the original idea comes from: [TamperingSyscalls](https://github.com/rad9800/TamperingSyscalls).

For now, this feature is implemented for the functions NtOpenProcess, NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory and NtCreateThreadEx. In order to use it, it's just needed to activate the feature, set the exception handler and call the desired function through Dinvoke.

```rust

use data::{THREAD_ALL_ACCESS, CLIENT_ID};
use windows::{Win32::Foundation::HANDLE, Wdk::Foundation::OBJECT_ATTRIBUTES};

fn main() {
    unsafe
    {
        // We active the use of hardware breakpoints to spoof syscall parameters
        dinvoke::use_hardware_breakpoints(true);
        // We get the memory address of our function and set it as the 
        // top-level exception handler.
        let handler = dinvoke::breakpoint_handler as usize;
        dinvoke::set_unhandled_exception_filter(handler);

        let h = HANDLE {0: -1};
        let handle: *mut HANDLE = std::mem::transmute(&h);
        let access = THREAD_ALL_ACCESS; 
        let a = OBJECT_ATTRIBUTES::default(); // https://github.com/Kudaes/rust_tips_and_tricks/tree/main#transmute
        let attributes: *mut OBJECT_ATTRIBUTES = std::mem::transmute(&a);
        // We set the PID of the remote process 
        let remote_pid = 10952isize;
        let c = CLIENT_ID {unique_process: HANDLE {0: remote_pid}, unique_thread: HANDLE::default()};
        let client_id: *mut CLIENT_ID = std::mem::transmute(&c);
        // A call to NtOpenProcess is performed through Dinvoke. The parameters will be
        // automatically spoofed by the function and restored to the original values
        // before executing the syscall.
        let ret = dinvoke::nt_open_process(handle, access, attributes, client_id);

        println!("NTSTATUS: {:x}", ret);
    }
}

```