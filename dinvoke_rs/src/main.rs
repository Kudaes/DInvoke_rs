use data::{THREAD_ALL_ACCESS, CLIENT_ID};
use dmanager::Manager;
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