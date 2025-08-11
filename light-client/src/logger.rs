use alloc::vec::Vec;

extern "C" {
    fn ocall_info(msg: *const i8);
    fn ocall_debug(msg: *const i8);
}

#[no_mangle]
pub extern "C" fn info(msg: &str) {
    let mut buf: Vec<u8> = msg.as_bytes().to_vec();
    buf.push(0); // Append NUL terminator

    unsafe {
        ocall_info(buf.as_ptr() as *const i8);
    }
}

#[no_mangle]
pub extern "C" fn debug(msg: &str) {
    let mut buf: Vec<u8> = msg.as_bytes().to_vec();
    buf.push(0); // Append NUL terminator

    unsafe {
        ocall_debug(buf.as_ptr() as *const i8);
    }
}
