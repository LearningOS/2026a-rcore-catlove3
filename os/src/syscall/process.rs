//! Process management syscalls

use crate::mm::{translated_byte_buffer, MapPermission, VirtAddr};
use crate::timer::get_time_us;
use crate::{
    loader::get_app_data_by_name,
    mm::{translated_refmut, translated_str},
    task::{
        add_task, current_task, current_user_token, exit_current_and_run_next,
        suspend_current_and_run_next,
    },
};
use alloc::sync::Arc;

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(exit_code: i32) -> ! {
    trace!("kernel:pid[{}] sys_exit", current_task().unwrap().pid.0);
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel:pid[{}] sys_yield", current_task().unwrap().pid.0);
    suspend_current_and_run_next();
    0
}

pub fn sys_getpid() -> isize {
    trace!("kernel: sys_getpid pid:{}", current_task().unwrap().pid.0);
    current_task().unwrap().pid.0 as isize
}

pub fn sys_fork() -> isize {
    trace!("kernel:pid[{}] sys_fork", current_task().unwrap().pid.0);
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

pub fn sys_exec(path: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_exec", current_task().unwrap().pid.0);
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(data) = get_app_data_by_name(path.as_str()) {
        let task = current_task().unwrap();
        task.exec(data);
        0
    } else {
        -1
    }
}

/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    trace!(
        "kernel::pid[{}] sys_waitpid [{}]",
        current_task().unwrap().pid.0,
        pid
    );
    let task = current_task().unwrap();
    // find a child process

    // ---- access current PCB exclusively
    let mut inner = task.inner_exclusive_access();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.getpid())
    {
        return -1;
        // ---- release current PCB
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily access child PCB exclusively
        p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after being removed from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily access child PCB exclusively
        let exit_code = child.inner_exclusive_access().exit_code;
        // ++++ release child PCB
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB automatically
}

/// Write time to the user buffer, including across page boundaries.
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel:pid[{}] sys_get_time", current_task().unwrap().pid.0);
    let time = get_time_us();
    let sec = (time / 1_000_000).to_ne_bytes();
    let usec = (time % 1_000_000).to_ne_bytes();
    let mut bytes = [0u8; core::mem::size_of::<TimeVal>()];
    bytes[..sec.len()].copy_from_slice(&sec);
    bytes[sec.len()..].copy_from_slice(&usec);

    let token = current_user_token();
    let buffer = translated_byte_buffer(token, ts as *const u8, bytes.len());

    let mut offset = 0;
    for part in buffer {
        let end = offset + part.len();
        part.copy_from_slice(&bytes[offset..end]);
        offset = end;
    }

    0
}

/// Validate an aligned user range before converting its addresses to Sv39.
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

/// Map anonymous user pages, checking overlap and available physical frames.
pub fn sys_mmap(start: usize, len: usize, prot: usize) -> isize {
    if prot == 0 || prot & !0x7 != 0 {
        return -1;
    }
    let Some((start_va, end_va)) = user_map_range(start, len) else {
        return -1;
    };
    if len == 0 {
        return 0;
    }
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    let perm = MapPermission::U | MapPermission::from_bits_truncate((prot as u8) << 1);
    if inner
        .memory_set
        .try_insert_framed_area(start_va, end_va, perm)
    {
        0
    } else {
        -1
    }
}

/// Remove a validated user range and return its data frames.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    let Some((start_va, end_va)) = user_map_range(start, len) else {
        return -1;
    };
    if len == 0 {
        return 0;
    }
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    if inner
        .memory_set
        .unmap_user_range(start_va.floor(), end_va.ceil())
    {
        0
    } else {
        -1
    }
}

/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel:pid[{}] sys_sbrk", current_task().unwrap().pid.0);
    if let Some(old_brk) = current_task().unwrap().change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}

/// Create a child process from the named ELF program.
pub fn sys_spawn(path: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_spawn", current_task().unwrap().pid.0);

    let token = current_user_token();
    let file_path = translated_str(token, path);

    if let Some(data) = get_app_data_by_name(file_path.as_str()) {
        let current_task = current_task().unwrap();
        let pid = current_task.spawn(data);
        pid
    } else {
        -1
    }
}

/// Set the current task priority, accepting values of at least two.
pub fn sys_set_priority(prio: isize) -> isize {
    trace!(
        "kernel:pid[{}] sys_set_priority",
        current_task().unwrap().pid.0
    );

    if prio <= 1 {
        return -1;
    }

    let current_task = current_task();
    current_task.unwrap().inner_exclusive_access().priority = prio as usize;

    prio
}
