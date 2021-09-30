//use std::ffi::CString;
//use bindings::Windows::Win32::Foundation::{FARPROC, HINSTANCE, PSTR};

//type func = extern "system" fn (PSTR) -> HINSTANCE;
fn main() {
    println!("Hello, world!");
   /*/ unsafe {
        let name = CString::new("LoadLibraryA".to_string()).expect("CString::new failed");
        let function_name = PSTR{0: name.as_ptr() as *mut u8};
        let function_ptr: extern "system" fn (HINSTANCE,PSTR) -> Option<FARPROC>;
        let a: func;
        let ret: Option<FARPROC>;
        let mut abc:HINSTANCE = HINSTANCE{0: 0};
        abc.0 = dinvoke::get_module_base_address(&"kernel32.dll".to_string()) as isize;
        dinvoke::dynamic_export!(&"kernel32.dll".to_string(),"GetProcAddress".to_string(),function_ptr,ret,abc,function_name);
        let s = dinvoke::get_function_address(abc.0 as i64, "LoadLibraryA".to_string());
        println!("{}", s);
        match ret {
            Some(X) => println!("{}", X as i64),
            None => println!("error"),
        }

    }*/
}


