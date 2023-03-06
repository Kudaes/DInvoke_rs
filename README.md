# DInvoke_rs

Rust port of [Dinvoke](https://github.com/TheWover/DInvoke). DInvoke_rs may be used for many purposes such as PE parsing, dynamic exported functions resolution, dynamically loading PE plugins at runtime, API hooks evasion and more. This project is meant to be used as a template (just add your own Rust code on top of it) or as a nested crate that can be imported on your own project.

Sinced this is a minimalist branch, it only offers the following features:
* Dynamically resolve and invoke undocumented Windows APIs from Rust.
* Primitives allowing for strategic API hook evasion. 
* Indirect syscalls. **x64 only**
* Syscall parameters spoofing through exception filter + hardware breakpoints. **x64 only**

# Credit
All the credits go to the creators of the original C# implementation of this tool:
* [The Wover](https://twitter.com/TheRealWover)
* [FuzzySec (b33f)](https://twitter.com/FuzzySec)
* [cobbr](https://twitter.com/cobbr_io)

I just created this port as a way to learn Rust myself and with the idea of facilitate to the Red Team community the transition from more common and known languages (like C++ or C#) to Rust to develop their hacking tools.  

# Usage

Since we are using [LITCRYPT](https://github.com/anvie/litcrypt.rs) plugin to obfuscate string literals, it is required to set up the environment variable LITCRYPT_ENCRYPT_KEY before compiling the code:

	C:\Users\User\Desktop\DInvoke.rs\dinvoke_rs> set LITCRYPT_ENCRYPT_KEY="yoursupersecretkey"

After that, you can open the project using your favorite IDE and start implementing your own code using all the functionalities offered by DInvoke_rs.
    
    C:\Users\User\Desktop\DInvoke.rs\dinvoke_rs> code .

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
In the example below, we use DInvoke_rs to dynamically call RtlAdjustPrivilege in order to enable SeDebugPrivilege for the current process token. This kind of execution will bypass any API hooks present in Win32. Also, it won't create any entry on the final PE Import Address Table, making it harder to detect the PE's behaviour without executing it.

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

# Example 3 - Executing indirect syscall
In the next example, we use DInvoke_rs to indirectly execute the syscall that corresponds to the function NtQueryInformationProcess. Since the macro dinvoke::execute_syscall!() dynamically allocates and executes the shellcode required to perform the desired syscall, all hooks present in ntdll.dll are bypassed. The memory allocated is released once the syscall returns, avoiding the permanent presence of memory pages with execution permission.

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
# Example 4 - Syscall parameters spoofing
In order to spoof the first 4 parameters of a syscall, DInvoke_rs has support for hardware breakpoints in combination with exception handlers. This allows to send not malicious parameters to a NT function, and after the EDR has inspected them, they are replaced by the original parameters before the syscall instruction is executed. For further information, check out the repository where the original idea came from: [TamperingSyscalls](https://github.com/rad9800/TamperingSyscalls).

For now, this feature is implemented for the functions NtOpenProcess, NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory and NtCreateThreadEx. In order to use it, it's just needed to activate the feature, set the exception handler and call the desired function through Dinvoke.

```rust

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
        let attributes: *mut OBJECT_ATTRIBUTES = std::mem::transmute(&OBJECT_ATTRIBUTES::default());
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
