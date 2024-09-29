# DInvoke_nostd

This branch contains the `no_std` version of Dinvoke_rs. DInvoke_nostd may be used for many purposes such as PE parsing, dynamic exported functions resolution, dynamically loading PEs at runtime and executiong indirect syscalls.

Features:
* Dynamically resolve and invoke undocumented Windows APIs from Rust.
* Indirect syscalls. **x64 only**
* Manually map PE modules from disk or directly from memory.
* PE headers parsing.

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
- [no_std features](#no_std-features)

# Usage

Import this crate into your project by adding the following line to your `cargo.toml`:

```rust
[dependencies]
dinvoke_nostd = "0.1.1"
```

It is required to statically link the VCRuntime to use this crate. To do so, add the following line to `cargo.toml`:

```rust
[build-dependencies]
static_vcruntime = "2.0"
```

Then, create a `build.rs` file at the root of your crate with the following content:

```rust
fn main() {
    static_vcruntime::metabuild();
}
```

Finally, compile the code with `cargo build --release`.

# Examples
## Resolving Exported APIs

The example below demonstrates how to use DInvoke_nostd to dynamically find and call exports of a DLL (`ntdll.dll` in this case).

1) Get ntdll's base address.
2) Use `get_function_address()` to find an export within `ntdll.dll` by name. This is achieved by walking and parsing the dll's EAT.
3) You can also find an export by ordinal by calling `get_function_address_by_ordinal()`. 

```rust
#![no_std]
#![no_main]
use core::fmt::Write;
use alloc::string::String;

#[no_mangle]
pub extern "C" fn main() {

    // Dynamically obtain ntdll.dll's base address. 
    let ntdll = dinvoke_nostd::dinvoke::get_module_base_address("ntdll.dll");

    if ntdll != 0 
    {
        dinvoke_nostd::utils::println!("ntdll.dll base address is 0x{:X}", ntdll);
        
        // Dynamically obtain the address of a function by name.
        let nt_create_thread = dinvoke_nostd::dinvoke::get_function_address(ntdll, "NtCreateThread");
        if nt_create_thread != 0 {
            dinvoke_nostd::utils::println!("NtCreateThread base address is 0x{:X}", nt_create_thread);
        }

        // Dynamically obtain the address of a function by ordinal.
        let ordinal_8 = dinvoke_nostd::dinvoke::get_function_address_by_ordinal(ntdll, 8);
        if ordinal_8 != 0 {
            dinvoke_nostd::utils::println!("The function with ordinal 8 is located at addresss 0x{:X}", ordinal_8);
        }
    }   
}

```

## Invoking Unmanaged Code
In the example below, we use Dinvoke_nostd to dynamically call `RtlAdjustPrivilege` in order to enable SeDebugPrivilege for the current process' token. This kind of execution will bypass any API hooks present in Win32. Also, it won't create any entry on the final PE's Import Address Table, making it harder to detect the PE's behaviour without executing it.

```rust
#![no_std]
#![no_main]
use core::fmt::Write;
use alloc::string::String;

#[no_mangle]
pub extern "C" fn main() {

    // Dynamically obtain ntdll.dll's base address. 
    let ntdll = dinvoke_nostd::dinvoke::get_module_base_address("ntdll.dll");

    if ntdll != 0 
    {
        unsafe 
        {
            let func_ptr:  unsafe extern "system" fn (u32, u8, u8, *mut u8) -> i32; // Function header available at data::RtlAdjustPrivilege
            let ret: Option<i32>; // RtlAdjustPrivilege returns an NSTATUS value, which is an i32
            let privilege: u32 = 20; // This value matches with SeDebugPrivilege
            let enable: u8 = 1; // Enable the privilege
            let current_thread: u8 = 0; // Enable the privilege for the current process, not only for the current thread
            let e = u8::default();
            let enabled: *mut u8 = core::mem::transmute(&e); 
            dinvoke_nostd::dinvoke::dynamic_invoke!(ntdll.1,"RtlAdjustPrivilege",func_ptr,ret,privilege,enable,current_thread,enabled);

            match ret {
                Some(x) => 
                    if x == 0 { /* dinvoke_nostd::dinvoke::print_str_to_console("NTSTATUS == Success. Privilege enabled."); */ } 
                    else { 
                        /* let mut s = String::new();
                        let _ = write!(s, "[x] NTSTATUS == {:X}", x as u32);
                        dinvoke_nostd::dinvoke::print_str_to_console(&s);  */
                        dinvoke_nostd::utils::println!("[x] NTSTATUS == {:X}", x as u32);
                        
                    },
                None => dinvoke_nostd::utils::println!("[x] Error!"),
            }
        } 
    }   
}


```

## Executing indirect syscall
In the next example, we use Dinvoke_nostd to execute the syscall corresponding to the function `NtDelayExecution `. The macro `indirect_syscall!()` will embbed in the resulting binary the code required to perform the indirect syscall, meaning that it won't be necessary to allocate additional private memory space in runtime to perform this technique.

```rust
#![no_std]
#![no_main]
use core::fmt::Write;
use alloc::string::String;

#[no_mangle]
pub extern "C" fn main() {

    unsafe 
    {
        let large = 0x8000000000000000 as u64; // Sleep indefinitely
        let large: *mut i64 = core::mem::transmute(&large);
        let alertable = false;
        let ntstatus = dinvoke_nostd::dinvoke::indirect_syscall!("NtDelayExecution", alertable, large); // returns *mut u8
        dinvoke_nostd::utils::println!("ntstatus: {:x}", ntstatus as i32);
    }
}

```

The macro expects the following parameters:

* The first parameter is a string that contains the name of the NT function whose syscall you want to execute.
* The following parameters are those arguments to send to the NT function.

In order to pass arguments to this macro, the following considerations must be taken into account:

* Any basic data type that can be converted to `usize` (u8-u64, i8-i64, bool, etc.) can be passed directly to the macro.
* Structs and unions of size 8, 16, 32, or 64 bits are passed as if they were integers of the same size.
* Structures and unions with a size larger than 64 bits must be passed as a pointer.
* Strings (`&str` and `String`) must be passed as a pointer.
* Null pointers (`ptr::null()`, `ptr::null_mut()`, etc. ) are passed as 0 (it doesn't matter if it is `0u8`, `0u16`, `0i32` or any other numeric type).
* Floating-point and double-precision parameters are not currently supported. 
* Any other data type must be passed as a pointer.

The macro directly returns the value contained in the `rax` value after the called Nt function returns. This value is represented as a `*mut u8` that should be converted to the data type expected from the called function. For example, if the called Nt function returns an `NTSTATUS`, the obtained `*mut u8` should be converted to `i32` allowing to correctly interact with the returned `NTSTATUS`. This process is performed in the example above.

## Manual PE mapping
In this example, Dinvoke_nostd is used to manually map a fresh copy of `ntdll.dll`, without any EDR hooks. Then that fresh ntdll.dll copy can be used to execute any desired function. 

This manual map can also be executed from memory (use `manually_map_module()` in that case), allowing to perform the classic reflective dll injection (current process only).

```rust
#![no_std]
#![no_main]
use core::fmt::Write;
use alloc::string::String;
use dinvoke_nostd::data::PeMetadata;

#[no_mangle]
pub extern "C" fn main()  {

    unsafe 
    {

        let ntdll: (PeMetadata, usize) = dinvoke_nostd::manualmap::read_and_map_module(r"C:\Windows\System32\ntdll.dll", true, false).unwrap();
        let func_ptr:  unsafe extern "system" fn (u32, u8, u8, *mut u8) -> i32; // Function header available at data::RtlAdjustPrivilege
        let ret: Option<i32>; // RtlAdjustPrivilege returns an NSTATUS value, which is an i32
        let privilege: u32 = 20; // This value matches with SeDebugPrivilege
        let enable: u8 = 1; // Enable the privilege
        let current_thread: u8 = 0; // Enable the privilege for the current process, not only for the current thread
        let e = u8::default();
        let enabled: *mut u8 = core::mem::transmute(&e); 
        dinvoke_nostd::dinvoke::dynamic_invoke!(ntdll.1,"RtlAdjustPrivilege",func_ptr,ret,privilege,enable,current_thread,enabled);

        match ret {
            Some(x) => 
                if x == 0 { 
                    dinvoke_nostd::utils::println!("Success!");
                } else { 
                    dinvoke_nostd::utils::println!("[x] NTSTATUS == {:X}", x as u32);
                },
            None => dinvoke_nostd::utils::println!("[x] Error!"),
        }
    }
}

```

## no_std features
Since this crate is meant to be used in a `no_std` environment, two functions have been added to the `utils` crate to facilitate the experience of the developer:

* The `read_file` function allows to read the binary content of an existing file, returning a `Vec<u8>` with such contents.
* The `println!()` macro is a simplified version of the `std::println!()` macro, allowing to print to the standard output. 