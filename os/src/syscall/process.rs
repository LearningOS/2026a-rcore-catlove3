//! Process management syscalls
//!
//! The syscall arguments and error cases follow the chapter 4 exercises:
//! <https://learningos.cn/rCore-Tutorial-Guide/chapter4/7exercise.html>.
//! See `reports/lab2.md` for the discussion of cross-page writes and user permissions.

use crate::mm::{translated_byte_buffer, MapPermission, PTEFlags, PageTable, VirtAddr};
use crate::task::{
    change_program_brk, current_syscall_count, current_user_token, exit_current_and_run_next,
    map_current_area, suspend_current_and_run_next, unmap_current_area,
};
use crate::timer::get_time_us;
use core::mem;

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// Write seconds and microseconds to the user's buffer, including across page boundaries.
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");

    let us: usize = get_time_us();
    let sec = (us / 1_000_000).to_ne_bytes();
    let usec = (us % 1_000_000).to_ne_bytes();

    let mut bytes = [0u8; mem::size_of::<TimeVal>()];
    bytes[..sec.len()].copy_from_slice(&sec);
    bytes[sec.len()..].copy_from_slice(&usec);

    let buffers = translated_byte_buffer(
        current_user_token(),
        ts as *const u8,
        mem::size_of::<TimeVal>(),
    );

    let mut offset = 0;
    for buffer in buffers {
        let end = offset + buffer.len();
        buffer.copy_from_slice(&bytes[offset..end]);
        offset = end;
    }

    0
}

/// Read or write one user byte, or query this task's syscall count.
pub fn sys_trace(_trace_request: usize, _id: usize, _data: usize) -> isize {
    trace!("kernel: sys_trace");
    match _trace_request {
        // VirtAddr::from keeps only the low 39 bits. Reject noncanonical addresses.
        0 | 1 if usize::from(VirtAddr::from(_id)) != _id => -1,
        0 => {
            let page_table = PageTable::from_token(current_user_token());
            let va = VirtAddr::from(_id);

            let entry = page_table.translate(va.floor());
            if entry.is_none() {
                return -1isize;
            }

            let pte = entry.unwrap();
            if !pte.is_valid() || !pte.flags().contains(PTEFlags::U) || !pte.readable() {
                return -1isize;
            }

            let bytes = pte.ppn().get_bytes_array();
            bytes[va.page_offset()] as isize
        }
        1 => {
            let page_table = PageTable::from_token(current_user_token());
            let va = VirtAddr::from(_id);

            let entry = page_table.translate(va.floor());
            if entry.is_none() {
                return -1isize;
            }

            let pte = entry.unwrap();
            if !pte.is_valid() || !pte.flags().contains(PTEFlags::U) || !pte.writable() {
                return -1isize;
            }

            let bytes = pte.ppn().get_bytes_array();
            bytes[va.page_offset()] = _data as u8;

            0
        }
        2 => current_syscall_count(_id) as isize,
        _ => -1isize,
    }
}

/// Validate the half-open user range before narrowing addresses to Sv39.
fn user_map_range(start: usize, len: usize) -> Option<(VirtAddr, VirtAddr)> {
    let start_va = VirtAddr::from(start);
    if usize::from(start_va) != start || !start_va.aligned() {
        return None;
    }
    let end = start.checked_add(len)?;
    let end_va = VirtAddr::from(end);
    if len != 0 && usize::from(VirtAddr::from(end - 1)) != end - 1 {
        return None;
    }
    // Both endpoints can be canonical while the range crosses the Sv39 hole.
    if end_va.0.checked_sub(start_va.0) != Some(len) {
        return None;
    }
    Some((start_va, end_va))
}

/// Map anonymous pages in the current task's address space.
pub fn sys_mmap(start: usize, len: usize, prot: usize) -> isize {
    trace!("kernel: sys_mmap!");
    if prot & !0x7 != 0 || prot == 0 {
        return -1;
    }
    let Some((start_va, end_va)) = user_map_range(start, len) else {
        return -1;
    };
    if len == 0 {
        return 0;
    }
    let perm = MapPermission::U | MapPermission::from_bits_truncate((prot as u8) << 1);
    if map_current_area(start_va, end_va, perm) {
        0
    } else {
        -1
    }
}

/// Unmap user pages in the current task's address space.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap!");
    let Some((start_va, end_va)) = user_map_range(start, len) else {
        return -1;
    };
    if len == 0 {
        return 0;
    }
    if unmap_current_area(start_va.floor(), end_va.ceil()) {
        0
    } else {
        -1
    }
}

/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
