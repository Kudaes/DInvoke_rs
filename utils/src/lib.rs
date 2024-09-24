#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use data::{CloseHandle, CreateFileW, GetProcessHeap, GetStdHandle, HeapAlloc, HeapFree, ReadFile, WriteConsoleW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, HANDLE, HEAP_ZERO_MEMORY, OPEN_EXISTING, STD_OUTPUT_HANDLE};
use core::ptr::{self, copy_nonoverlapping, null_mut};
use core::ffi::c_void;
use alloc::string::{String, ToString};

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
            return Err("Error opening the file.".to_string());
        }
    
        let mut buffer_size: usize = 4096;
        let process_heap = GetProcessHeap();
        let mut file_buffer = HeapAlloc(process_heap, HEAP_ZERO_MEMORY, buffer_size);
    
        if file_buffer.is_null() 
        {
            CloseHandle(handle);
            return Err("Heap allocation failed".to_string());
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
                        return Err("Error al reasignar memoria en el heap".to_string());
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
            return Err("Error reading file".to_string());
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


// This macro requires to import "core::fmt::Write;"
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

/* pub fn print_number_hex(number: usize) {
    let mut string = String::new();
    let _ = write!(string, "{:x}\n", number);  

    let mut utf16: Vec<u16> = string.encode_utf16().collect();  
    utf16.push(0);

    unsafe {
        let h_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
        if !h_stdout.is_null() {
            WriteConsoleW(
                h_stdout,
                utf16.as_ptr(),
                utf16.len() as u32,
                ptr::null_mut(),
                ptr::null_mut(),
            );
        }
    } 
}

pub fn print_str_to_console(s: &str) {
    let mut string = String::new();
    let _ = write!(string, "{}\n", s);  

    let utf16: Vec<u16> = string.encode_utf16().collect();  

    unsafe {
        let h_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
        if !h_stdout.is_null() {
            WriteConsoleW(
                h_stdout,
                utf16.as_ptr(),
                utf16.len() as u32,
                ptr::null_mut(),
                ptr::null_mut(),
            );
        }
    } 
} */