#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::panic::PanicInfo;
use core::ptr::{self};
use core::ffi::c_void;

#[link(name = "psapi")]
extern "system" {
    pub fn GetStdHandle(nStdHandle: u32) -> *mut core::ffi::c_void;
    pub fn WriteConsoleW(
        hConsoleOutput: *mut core::ffi::c_void,
        lpBuffer: *const u16,
        nNumberOfCharsToWrite: u32,
        lpNumberOfCharsWritten: *mut u32,
        lpReserved: *mut core::ffi::c_void,
    ) -> i32; 
    pub fn EnumProcessModules(process_handle: HANDLE, hmodule: *mut usize, cb: u32, needed: *mut u32) -> i32;
    pub fn GetModuleBaseNameW(process_handle: HANDLE, hmodule: *mut usize, base_name: *mut u16, size: u32) -> u32;
    pub fn GetModuleFileNameExW(process_handle: HANDLE, hmodule: *mut usize, base_name: *mut u16, size: u32) -> u32;
}

#[link(name = "kernel32")]
extern "system" {
    pub fn CreateFileW(filename: *mut u16, desired_access: u32, share_mode: u32, security_attributes: *mut SecurityAttributes, disposition: u32, flags: u32, template_file: HANDLE) -> HANDLE;
    pub fn GetCurrentProcess() -> HANDLE;
    pub fn CloseHandle(handle: HANDLE) -> bool;
    pub fn GetProcessHeap() -> HANDLE;
    pub fn HeapAlloc(handle: HANDLE, flags: u32, size: SizeT) -> PVOID;
    pub fn HeapFree(handle: HANDLE, flags: u32, memory_ptr: PVOID) -> bool;
    pub fn ReadFile(handle: HANDLE, buffer: *mut c_void, bytes_to_read: u32, bytes_read: *mut u32, overlapped: *mut Overlapped) -> bool;
}

extern "C" {
    fn _aligned_malloc(size: SizeT, align: SizeT) -> *mut c_void;
    fn _aligned_realloc(p: *mut c_void, size: SizeT, align: SizeT) -> *mut c_void;
    fn _aligned_free(p: *mut c_void);
}

pub struct WindowsHeapAllocator;

// Obtained from https://github.com/daniel5151/libc_alloc/blob/master/src/win_crt.rs
unsafe impl GlobalAlloc for WindowsHeapAllocator {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        _aligned_malloc(layout.size(), layout.align()) as *mut u8
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        _aligned_free(ptr as *mut c_void)
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // Unfortunately, _aligned_calloc does not exist, so the memory
        // has to be manually zeroed-out.
        let ptr = self.alloc(layout);
        if !ptr.is_null() {
            ptr::write_bytes(ptr, 0, layout.size());
        }
        ptr
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        _aligned_realloc(ptr as *mut c_void, new_size, layout.align()) as *mut u8
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {} //Something should be done with this
}

pub type SizeT = usize;
pub type NtQueryInformationProcess = unsafe extern "system" fn (HANDLE, u32, *mut c_void, u32, *mut u32) -> i32;
pub type NtAllocateVirtualMemory = unsafe extern "system" fn (HANDLE, *mut PVOID, usize, *mut usize, u32, u32) -> i32;
pub type NtWriteVirtualMemory = unsafe extern "system" fn (HANDLE, PVOID, PVOID, usize, *mut usize) -> i32;
pub type NtProtectVirtualMemory = unsafe extern "system" fn (HANDLE, *mut PVOID, *mut usize, u32, *mut u32) -> i32;
pub type RtlAddFunctionTable = unsafe extern "system" fn (usize, i32, usize) -> bool;
pub type RtlGetVersion = unsafe extern "system" fn (*mut OSVERSIONINFOW) -> i32;
pub type LdrGetProcedureAddress = unsafe extern "system" fn (PVOID, *mut String, u32, *mut PVOID) -> i32;
pub type LoadLibraryA = unsafe extern "system" fn (*mut u8) -> usize;
pub type EAT = BTreeMap<usize,String>;
pub type PVOID = *mut c_void;

pub const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
pub const MAX_PATH: u32 = 260;

pub const FILE_GENERIC_READ: u32 = 0x120089;
pub const OPEN_EXISTING: u32 = 0x3;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

pub const HEAP_ZERO_MEMORY: u32 = 0x00000008;

pub const PAGE_NOACCESS: u32 = 0x1;
pub const PAGE_READONLY: u32 = 0x2;
pub const PAGE_READWRITE: u32 = 0x4;
pub const PAGE_WRITECOPY: u32 = 0x8;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;

pub const SECTION_MEM_READ: u32 = 0x40000000;
pub const SECTION_MEM_WRITE: u32 = 0x80000000;
pub const SECTION_MEM_EXECUTE: u32 = 0x20000000;

#[repr(C)]
#[derive(Copy, Clone, Default, PartialEq, Debug, Eq)]
pub struct HANDLE {
    pub id: isize,
}

#[repr(C)]
pub struct SecurityAttributes {
    pub length: u32,
    pub security_descriptor: *mut c_void,
    pub inherit_handle: bool,
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

#[repr(C)]
#[derive(Copy, Clone, Default, PartialEq, Debug, Eq)]
pub struct ProcessBasicInformation {
    pub exit_status: i32, //NTSTATUS
    pub peb_base_address: usize, // This should be *mut PEB, but whatever 
    pub affinity_mask: usize,
    pub base_priority: i32,
    pub unique_process_id: usize,
    pub inherited_from_unique_process_id: usize,
}

#[repr(C)]
pub struct Overlapped {
    pub internal: usize,
    pub internal_high: usize,
    pub anonymous: *mut c_void,
    pub h_event: HANDLE,
}

#[derive(Clone)]
#[repr(C)]
pub struct PeMetadata {
    pub pe: u32,
    pub is_32_bit: bool,
    pub image_file_header: ImageFileHeader,
    pub opt_header_32: ImageOptionalHeader32,
    pub opt_header_64: ImageOptionalHeader64,
    pub sections: Vec<ImageSectionHeader> 
}

impl Default for PeMetadata {
    fn default() -> PeMetadata {
        PeMetadata {
            pe: u32::default(),
            is_32_bit: false,
            image_file_header: ImageFileHeader::default(),
            opt_header_32: ImageOptionalHeader32::default(),
            opt_header_64: ImageOptionalHeader64::default(),
            sections: Vec::default(),  
        }
    }
}

#[derive(Copy, Clone, Default, PartialEq, Debug, Eq)]
#[repr(C)]
pub struct ImageFileHeader {
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
pub struct ImageOptionalHeader64 {
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
        pub datas_directory: [ImageDataDirectory; 16], 
}

#[derive(Copy, Clone,Default)]
#[repr(C)] // required to keep fields order, otherwise Rust may change that order randomly
pub struct ImageOptionalHeader32 {
        pub magic: u16, 
        pub major_linker_version: u8, 
        pub minor_linker_version: u8, 
        pub size_of_code: u32, 
        pub size_of_initialized_data: u32, 
        pub size_of_unitialized_data: u32, 
        pub address_of_entry_point: u32, 
        pub base_of_code: u32, 
        pub image_base: u32, 
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
        pub size_of_stack_reserve: u32, 
        pub size_of_stack_commit: u32, 
        pub size_of_heap_reserve: u32, 
        pub size_of_heap_commit: u32, 
        pub loader_flags: u32, 
        pub number_of_rva_and_sizes: u32, 
        pub datas_directory: [ImageDataDirectory; 16], 
}

#[derive(Copy, Clone,Default)]
#[repr(C)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[derive(Copy, Clone,Default)]
#[repr(C)]
pub struct ImageBaseRelocation {
    pub virtual_address: u32,
    pub size_of_block: u32,
}

#[derive(Copy, Clone,Default)]
#[repr(C)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],
    pub misc: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

#[repr(C)]
pub struct OSVERSIONINFOW {
    pub dw_osversion_info_size: u32,
    pub dw_major_version: u32,
    pub dw_minor_version: u32,
    pub dw_build_number: u32,
    pub dw_platform_id: u32,
    pub sz_csdversion: [u16; 128],
}

#[derive(Copy, Clone,Default)]
#[repr(C)]
pub struct ImageImportDescriptor {
    pub anonymous: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,
    pub first_thunk: u32,
}