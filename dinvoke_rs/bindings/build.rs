fn main() {
    windows::build!(
        Windows::Win32::System::Diagnostics::Debug::{WriteProcessMemory,IMAGE_FILE_HEADER,IMAGE_OPTIONAL_HEADER32,IMAGE_SECTION_HEADER,
            IMAGE_DATA_DIRECTORY,IMAGE_OPTIONAL_HEADER_MAGIC,IMAGE_SUBSYSTEM},
        Windows::Win32::System::Memory::{VIRTUAL_ALLOCATION_TYPE,PAGE_PROTECTION_FLAGS,VirtualAlloc,VirtualProtect,VirtualFree},
        Windows::Win32::Foundation::{HANDLE,HINSTANCE,PSTR},
        Windows::Win32::System::Threading::{GetCurrentProcess,NtQueryInformationProcess,PROCESS_BASIC_INFORMATION,PROCESSINFOCLASS},
        Windows::Win32::System::SystemServices::{IMAGE_BASE_RELOCATION,IMAGE_IMPORT_DESCRIPTOR,IMAGE_THUNK_DATA32,IMAGE_THUNK_DATA64},
        Windows::Win32::System::LibraryLoader::GetProcAddress,
    );
}