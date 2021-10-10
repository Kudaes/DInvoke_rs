# DInvoke_rs

Rust port of [Dinvoke](https://github.com/TheWover/DInvoke). DInvoke_rs may be used for many purposes such as PE parsing, dynamic exported functions resolution, dynamically loading PE plugins at runtime, API hooks evasion and more. This project is meant to be used as a template (just add your own Rust code on top of it) or as a nested crate that can be imported on your own project (remove the src package and compile it as a lib).

Features:
* Dynamically resolve and invoke undocumented Windows APIs from Rust.
* Primitives allowing for strategic API hook evasion. 
* Direct syscall execution from Rust.
* Manually map PE modules from disk or directly from memory.
* PE headers parsing.

TODO:
* Map PE modules into sections backed by arbitrary modules on disk.
* PE headers manipulation.

# Credit
All the credits go to the creators of the original C# implementation of this tool:
* [The Wover](https://twitter.com/TheRealWover)
* [FuzzySec (b33f)](https://twitter.com/FuzzySec)
* [cobbr](https://twitter.com/cobbr_io)

I just created this port as a way to learn Rust myself and with the idea of facilitate to the Red Team community the transition from more common and known languages (like C++ or C#) to Rust to develop their hacking tools.  

# Compile requirements

Since we are using [LITCRYPT](https://github.com/anvie/litcrypt.rs) plugin to obfuscate string literals, it is required to set up the environment variable LITCRYPT_ENCRYPT_KEY before compiling the code:

	set LITCRYPT_ENCRYPT_KEY="yoursupersecretkey"

If you dont set up this environment variable you will se a lot of errors at the time of opening the project or importing the code into your own crate. This feature will probably be removed in the near future since LLVM string obfuscation may be a better approach.

# Example 1 - Resolving Exported Unmanaged APIs

The example below demonstrates how to use DInvoke_rs to dynamically find and call exports of a DLL.

1) Get the base address of ntdll.dll by walking the Process Environment Block.
2) Use get_function_address() to find an export within ntdll.dll by name. This is done by walking and parsing the module's EAT.
3) Use get_function_address_by_ordinal() to find an export within ntdll.dll by ordinal. This is done by dynamically calling LdrGetProcedureAddress.

```rust

fn main() {

    // Dynamically obtain the base address of ntdll.dll. 
    let ntdll = dinvoke::get_module_base_address("ntdll.dll");

    if ntdll != 0 
    {
        println!("ntdll.dll base address is 0x{:X}", ntdll);
        
        // Dynamically obtain the address of a function by name.
        let nt_create_thread = dinvoke::get_function_address(ntdll, "NtCreateThread");
        if nt_create_thread != 0
        {
            println!("The address where NtCreateThread is located at is 0x{:X}", nt_create_thread);
        }

        // Dynamically obtain the address of a function by ordinal.
        let ordinal_8 = dinvoke::get_function_address_by_ordinal(ntdll, 8);
        if ordinal_8 != 0 
        {
            println!("The function with ordinal 8 is located at 0x{:X}", ordinal_8);
        }
    }   
}

```

# Example 2 - Invoking Unmanaged Code
In the example below, we use DInvoke_rs to dynamically call RtlAdjustPrivilege in order to enable SeDebugPrivilege for the current process token. This kind of execution will bypass any API hooks present in Win32. Also, it won't create any entry on the final PE Import Address Table, making it harder to detect the PE behaviour without executing it.

```rust

fn main() {

    // Dynamically obtain the base address of ntdll.dll. 
    let ntdll = dinvoke::get_module_base_address("ntdll.dll");

    if ntdll != 0 
    {
        unsafe 
        {
            let func_ptr:  unsafe extern "system" fn (u32, u8, u8, *mut u8) -> i32; // Function header available at data::RtlAdjustPrivilege
            let ret: Option<i32>; // RtlAdjustPrivilege returns an NSTATUS value, which is an i32
            let privilege: u32 = 20; // This value matches with SeDebugPrivilege
            let enable: u8 = 1; // Enable the privilege
            let current_thread: u8 = 0; // Enable the privilege for the current process, not only for the current thread
            let enabled: *mut u8 = std::mem::transmute(&u8::default()); 
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

# Example 3 - Executing direct syscall
In the next example, we use DInvoke_rs to execute the syscall that corresponds to function NtQueryInformationProcess. Since the macro dinvoke::execute_syscall!() dynamically allocates and executes the shellcode required to perform the desired syscall, all hooks present in ntdll.dll are bypassed.

```rust

use std::mem::size_of;
use bindings::Windows::Win32::System::Threading::{GetCurrentProcess, PROCESS_BASIC_INFORMATION};
use data::{NtQueryInformationProcess, PVOID};

fn main() {

    unsafe 
    {
        let function_type:NtQueryInformationProcess;
        let mut ret: Option<i32> = None; //NtQueryInformationProcess returns a NTSTATUS, which is a i32.
        let handle = GetCurrentProcess();
        let process_information: PVOID = std::mem::transmute(&PROCESS_BASIC_INFORMATION::default()); 
        let return_length: *mut u32 = std::mem::transmute(&u32::default());
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

```

# Example 4 - Manual PE mapping
In this last example, DInvoke_rs is used to manually map a fresh copy of ntdll.dll, without any EDR hooks. Then that fresh ntdll.dll copy can be used to execute any desired function. 

This manual map can also be executed from memory (use manually_map_module() in that case), allowing the classic reflective dll injection.

```rust

fn main() {

    unsafe 
    {

        let ntdll = manualmap::read_and_map_module("C:\\Windows\\System32\\ntdll.dll").unwrap();
        
        let func_ptr:  unsafe extern "system" fn (u32, u8, u8, *mut u8) -> i32; // Function header available at data::RtlAdjustPrivilege
        let ret: Option<i32>; // RtlAdjustPrivilege returns an NSTATUS value, which is an i32
        let privilege: u32 = 20; // This value matches with SeDebugPrivilege
        let enable: u8 = 1; // Enable the privilege
        let current_thread: u8 = 0; // Enable the privilege for the current process, not only for the current thread
        let enabled: *mut u8 = std::mem::transmute(&u8::default()); 
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
