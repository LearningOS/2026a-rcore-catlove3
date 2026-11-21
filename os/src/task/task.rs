//! Types related to task management

use super::TaskContext;

/// Maximum number of system calls tracked for each task
pub const MAX_SYSCALLS: usize = 512;

/// The task control block (TCB) of a task.
#[derive(Copy, Clone)]
pub struct TaskControlBlock {
    /// The task status in it's lifecycle
    pub task_status: TaskStatus,
    /// The task context
    pub task_cx: TaskContext,
    /// Number of calls to each system call, indexed by syscall ID.
    pub syscall_times: [u32; MAX_SYSCALLS],
}

/// The status of a task
#[derive(Copy, Clone, PartialEq)]
pub enum TaskStatus {
    /// uninitialized
    UnInit,
    /// ready to run
    Ready,
    /// running
    Running,
    /// exited
    Exited,
}
