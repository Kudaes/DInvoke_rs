//use bindings::Windows::Win32::Foundation::{HINSTANCE, PSTR};
//use data::LoadLibraryA;
//use std::ffi::CString;

fn main() {
    println!("Hello, world!");
    //let a = manualmap::read_and_map_module("C:\\Users\\PcCom\\Desktop\\hello.dll".to_string()).unwrap();
    //let ret = dinvoke::call_module_entry_point(&a.0, a.1);

   /* unsafe {
        let function_ptr: LoadLibraryA; 
        let name = CString::new("kernel32.dll".to_string()).expect("CString::new failed");
        let function_name = PSTR{0: name.as_ptr() as *mut u8};
        let mut abc: Option<HINSTANCE> = Option::None;
        let ptr = dinvoke::get_module_base_address(&"kernel32.dll".to_string());
        dinvoke::dynamic_invoke!(ptr,"LoadLibraryA",function_ptr,abc,function_name);

        match abc {
            Some(x) => println!("0x{:x}", x.0),
            None => println!("Error"),
        }
    }*/
}


