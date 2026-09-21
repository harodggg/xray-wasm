use super::{REACTOR, Reactor};

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

/// Start the event loop. Blocks until the future
pub fn block_on<F>(fut: F) -> F::Output
where
    F: Future,
{
    // Construct the reactor
    let reactor = Reactor::new();
    // Store a copy as a singleton to be used elsewhere:
    let prev = REACTOR.replace(Some(reactor.clone()));
    if prev.is_some() {
        panic!("cannot wstd::runtime::block_on inside an existing block_on!")
    }

    // Spawn the task onto the reactor.
    // Safety: The execution loop below, concluding with pulling the Ready out
    // of the root_task, ensures that it does not outlive the Future or its
    // output.
    #[allow(unsafe_code)]
    let root_task = unsafe { reactor.spawn_unchecked(fut) };

    // ─────────── 本地补丁（xray-wasm · V24 诊断）───────────
    // 在**反应器循环内部**（不依赖任何任务被调度）按 0.5s 打一行心跳。
    // 用途：V24 空转时 guest 任务全部拿不到时间片（连自己的心跳都停），
    // 只有循环本身还能打印。`WSTD_DIAG=1` 打开，缺省零行为改变。
    let diag = std::env::var_os("WSTD_DIAG").is_some();
    let mut iters: u64 = 0;
    let mut t_report = std::time::Instant::now();

    loop {
        iters += 1;
        if diag && t_report.elapsed().as_millis() >= 500 {
            let (calls, targets, ready) = reactor.diag_take();
            eprintln!(
                "[wstddiag] Δ{:.2}s iters={} pending_empty={} ready_list={} | poll_calls={} targets={} ready_idx={}",
                t_report.elapsed().as_secs_f64(),
                iters,
                reactor.pending_pollables_is_empty(),
                if reactor.ready_list_is_empty() { 0 } else { 1 },
                calls,
                targets,
                ready,
            );
            iters = 0;
            t_report = std::time::Instant::now();
        }
        match reactor.pop_ready_list() {
            // No more work is possible - only a pending pollable could
            // possibly create a runnable, and there are none.
            None if reactor.pending_pollables_is_empty() => break,
            // Block until a pending pollable puts something on the ready
            // list.
            None => reactor.block_on_pollables(),
            Some(runnable) => {
                // Run the task popped from the head of the ready list. If the
                // task re-inserts itself onto the runlist during execution,
                // last_run_awake is a hint that guarantees us the runlist is
                // nonempty.
                let last_run_awake = runnable.run();

                // If any task is ready for running, we perform a nonblocking
                // check of pollables, giving any tasks waiting on a pollable
                // a chance to wake.
                if last_run_awake || !reactor.ready_list_is_empty() {
                    reactor.nonblock_check_pollables();
                }
            }
        }
    }
    // Clear the singleton
    REACTOR.replace(None);
    // Get the result out of the root task
    let mut root_task = pin!(root_task);
    let mut noop_context = Context::from_waker(Waker::noop());
    match root_task.as_mut().poll(&mut noop_context) {
        Poll::Ready(res) => res,
        Poll::Pending => {
            unreachable!(
                "ready list empty, therefore root task should be ready. malformed root task?"
            )
        }
    }
}
