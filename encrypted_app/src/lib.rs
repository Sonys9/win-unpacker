#![no_std]
#![no_main]

use core::{ffi::c_void, panic::PanicInfo};
use goldberg::goldberg_stmts;
use crate::apis::{FnWriteFile, WinApi, print, rand_actions};
use obfstr::obfstr;
mod apis;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[inline(always)]
fn execute<F, T>(func: F, h_std_out: *mut c_void, write_file: FnWriteFile) -> T
where
    F: FnOnce() -> T,
{
    goldberg_stmts! {
        rand_actions(h_std_out, write_file);
        let result = func();
        rand_actions(h_std_out, write_file);
        result
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn catch_me_if_you_can() {
    goldberg_stmts! {
        let win_api = WinApi::new();
        print(obfstr!("Successfuly loaded!\nKrutoy loader tut\n"), win_api.h_std_out, win_api.write_file);
    };
    loop {}
}
