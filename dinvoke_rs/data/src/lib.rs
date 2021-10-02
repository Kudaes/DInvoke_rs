use std::ffi::c_void;

use bindings::Windows::Win32::{Foundation::{BOOL, HINSTANCE, PSTR}, System::Diagnostics::Debug::{IMAGE_OPTIONAL_HEADER32, IMAGE_SECTION_HEADER, IMAGE_DATA_DIRECTORY}};

pub type PVOID = *mut c_void;
pub type EntryPoint =  extern "system" fn (HINSTANCE, u32, *mut c_void) -> BOOL;
pub type LoadLibraryA = extern "system" fn (PSTR) -> HINSTANCE;
pub type LdrGetProcedureAddress = unsafe extern "system" fn (PVOID, *mut String, u32, *mut PVOID) -> i32;

pub const DLL_PROCESS_DETACH: u32 = 0;
pub const DLL_PROCESS_ATTACH: u32 = 1;
pub const DLL_THREAD_ATTACH: u32 = 2;
pub const DLL_THREAD_DETACH: u32 = 3;

pub const PAGE_READONLY: u32 = 0x2;
pub const PAGE_READWRITE: u32 = 0x4;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE: u32 = 0x10;

pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;

pub const SECTION_MEM_READ: u32 = 0x40000000;
pub const SECTION_MEM_WRITE: u32 = 0x80000000;
pub const SECTION_MEM_EXECUTE: u32 = 0x20000000;



#[derive(Clone)]
#[repr(C)]
pub struct PeMetadata {
    pub pe: u32,
    pub is_32_bit: bool,
    pub image_file_header: IMAGE_FILE_HEADER,
    pub opt_header_32: IMAGE_OPTIONAL_HEADER32,
    pub opt_header_64: IMAGE_OPTIONAL_HEADER64,
    pub sections: Vec<IMAGE_SECTION_HEADER> 
}

impl Default for PeMetadata {
    fn default() -> PeMetadata {
        PeMetadata {
            pe: u32::default(),
            is_32_bit: false,
            image_file_header: IMAGE_FILE_HEADER::default(),
            opt_header_32: IMAGE_OPTIONAL_HEADER32::default(),
            opt_header_64: IMAGE_OPTIONAL_HEADER64::default(),
            sections: Vec::default(),  
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default, PartialEq, Debug, Eq)]
pub struct ApiSetNamespace {
    pub unused: [u8;12],
    pub count: i32, // offset 0x0C
    pub entry_offset: i32, // offset 0x10
}

#[repr(C)]
#[derive(Copy, Clone, Default, PartialEq, Debug, Eq)]
pub struct ApiSetNamespaceEntry {
    pub unused1: [u8;4],
    pub name_offset: i32, // offset 0x04
    pub name_length: i32, // offset 0x08
    pub unused2: [u8;4],
    pub value_offset: i32, // offset 0x10
    pub value_length: i32, // offset 0x14
}

#[repr(C)]
#[derive(Copy, Clone, Default, PartialEq, Debug, Eq)]
pub struct ApiSetValueEntry {
    pub flags: i32, // offset 0x00
    pub name_offset: i32, // offset 0x04
    pub name_count: i32, // offset 0x08
    pub value_offset: i32, // offset 0x0C
    pub value_count: i32, // offset 0x10
}

#[derive(Copy, Clone, Default, PartialEq, Debug, Eq)]
#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_data_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[derive(Copy, Clone,Default)]
#[repr(C)] // required to keep fields order, otherwise Rust may change that order randomly
pub struct IMAGE_OPTIONAL_HEADER64 {
        pub magic: u16, 
        pub major_linker_version: u8, 
        pub minor_linker_version: u8, 
        pub size_of_code: u32, 
        pub size_of_initialized_data: u32, 
        pub size_of_unitialized_data: u32, 
        pub address_of_entry_point: u32, 
        pub base_of_code: u32, 
        pub image_base: u64, 
        pub section_alignment: u32, 
        pub file_alignment: u32, 
        pub major_operating_system_version: u16, 
        pub minor_operating_system_version: u16, 
        pub major_image_version: u16,
        pub minor_image_version: u16, 
        pub major_subsystem_version: u16,
        pub minor_subsystem_version: u16, 
        pub win32_version_value: u32, 
        pub size_of_image: u32, 
        pub size_of_headers: u32, 
        pub checksum: u32, 
        pub subsystem: u16, 
        pub dll_characteristics: u16, 
        pub size_of_stack_reserve: u64, 
        pub size_of_stack_commit: u64, 
        pub size_of_heap_reserve: u64, 
        pub size_of_heap_commit: u64, 
        pub loader_flags: u32, 
        pub number_of_rva_and_sizes: u32, 
        pub datas_directory: [IMAGE_DATA_DIRECTORY; 16], 
}
