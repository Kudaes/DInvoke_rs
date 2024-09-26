#![no_std]
#![no_main]

extern crate alloc;

#[macro_use]
extern crate litcrypt2;
use_litcrypt!();

use alloc::vec::Vec;
use data::{CloseHandle, CreateFileW, GetProcessHeap, GetStdHandle, HeapAlloc, HeapFree, ReadFile, WriteConsoleW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, HANDLE, HEAP_ZERO_MEMORY, OPEN_EXISTING, STD_OUTPUT_HANDLE};
use core::ptr::{self, copy_nonoverlapping, null_mut};
use core::ffi::c_void;
use alloc::string::String;


/// Reads the contents of a file.
///
/// # Examples
///
/// ```
/// let file_content = utils::read_file(r"c:\windows\system32\ntdll.dll")?;
/// ```
pub fn read_file(file_path: &str) -> Result<Vec<u8>, String> 
{
    unsafe 
    {
        let mut file_path: Vec<u16> = file_path.encode_utf16().collect();
        file_path.push(0);
    
        let handle: HANDLE = CreateFileW(
            file_path.as_mut_ptr(),
            FILE_GENERIC_READ,
            0,
            null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        );
    
        if handle.id == -1 {
            return Err(lc!("[x] Error opening the file."));
        }
    
        let mut buffer_size: usize = 4096;
        let process_heap = GetProcessHeap();
        let mut file_buffer = HeapAlloc(process_heap, HEAP_ZERO_MEMORY, buffer_size);
    
        if file_buffer.is_null() 
        {
            CloseHandle(handle);
            return Err(lc!("[x] Heap allocation failed"));
        }
    
        let mut bytes_read: u32 = 0;
        let mut total_bytes_read: usize = 0;
    
        loop 
        {
            let result = ReadFile(
                handle,
                file_buffer.add(total_bytes_read),
                4096,
                &mut bytes_read,
                null_mut(),
            );
    
            if result && bytes_read > 0 
            {
                total_bytes_read += bytes_read as usize;
    
                if total_bytes_read + 4096 > buffer_size 
                {
                    let new_buffer_size = buffer_size * 2;
                    let new_file_buffer = HeapAlloc(process_heap, HEAP_ZERO_MEMORY, new_buffer_size);
    
                    if new_file_buffer.is_null() 
                    {
                        HeapFree(process_heap, 0, file_buffer as *mut c_void); 
                        CloseHandle(handle);
                        return Err(lc!("[x] Heap allocation failed"));
                    }
    
                    copy_nonoverlapping(file_buffer as *mut u8, new_file_buffer as *mut u8, total_bytes_read);
    
                    HeapFree(process_heap, 0, file_buffer);
                    file_buffer = new_file_buffer;
                    buffer_size = new_buffer_size;
                }

            } else {
                break;
            }
        }
    
        CloseHandle(handle);
    
        if total_bytes_read == 0 {
            return Err(lc!("[x] Error reading the file."));
        }
        
        let new_file_buffer = HeapAlloc(process_heap, HEAP_ZERO_MEMORY, total_bytes_read);

        if new_file_buffer.is_null() {
            return Ok(Vec::from_raw_parts(file_buffer as *mut u8, total_bytes_read, total_bytes_read));
        }

        copy_nonoverlapping(file_buffer as *mut u8, new_file_buffer as *mut u8, total_bytes_read);
        HeapFree(process_heap, 0, file_buffer);
        
        Ok(Vec::from_raw_parts(new_file_buffer as *mut u8, total_bytes_read, total_bytes_read))
    }
}


/// This macro tries to reproduce the behavior of `std::println!()`.
/// 
/// The following lines should be added to use this macro:
/// ```
/// extern crate alloc;
/// use core::fmt::Write;
/// ```
///
/// # Examples
///
/// ```
/// extern crate alloc;
///
/// utils::println!("Hello world!");
/// utils::println!("Print hex value: {:x}", 2907isize);
/// utils::println!("{}{}", "Concat", "Strings");
/// ```
#[macro_export]
macro_rules!println {
    ($($arg:tt)*) => {
        let mut string = String::new();
        let _ = write!(string, $($arg)*);  
        let _ = write!(string, "\n");  
        let mut utf16: alloc::vec::Vec<u16> = string.encode_utf16().collect();  
        utf16.push(0);

        $crate::print_string(utf16);
    };
}

/// This function is not meant to be called directly, instead use `utils::println!()` macro.
pub fn print_string(utf16_str: Vec<u16>) {
    unsafe {
        let h_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
        if !h_stdout.is_null() {
            WriteConsoleW(
                h_stdout,
                utf16_str.as_ptr(),
                utf16_str.len() as u32,
                ptr::null_mut(),
                ptr::null_mut(),
            );
        }
    } 
}