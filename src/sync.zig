const std = @import("std");

pub fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

pub fn nanoTimestamp() i128 {
    return std.Io.Clock.awake.now(io()).nanoseconds;
}

pub fn timestamp() i64 {
    return std.Io.Clock.real.now(io()).toSeconds();
}

pub fn sleep(ns: u64) void {
    std.Io.sleep(io(), .fromNanoseconds(@intCast(ns)), .awake) catch unreachable;
}

pub const Mutex = struct {
    inner: std.Io.Mutex = .init,

    pub fn tryLock(self: *Mutex) bool {
        return self.inner.tryLock();
    }

    pub fn lock(self: *Mutex) void {
        self.inner.lockUncancelable(io());
    }

    pub fn unlock(self: *Mutex) void {
        self.inner.unlock(io());
    }
};

pub const Condition = struct {
    state: std.atomic.Value(State) = .init(.{ .waiters = 0, .signals = 0 }),
    epoch: std.atomic.Value(u32) = .init(0),

    const State = packed struct(u32) {
        waiters: u16,
        signals: u16,
    };

    pub fn wait(self: *Condition, mutex: *Mutex) void {
        var epoch = self.epoch.load(.acquire);
        const prev_state = self.state.fetchAdd(.{ .waiters = 1, .signals = 0 }, .monotonic);
        std.debug.assert(prev_state.waiters < std.math.maxInt(u16));

        mutex.unlock();
        defer mutex.lock();

        while (true) {
            io().futexWaitUncancelable(u32, &self.epoch.raw, epoch);
            epoch = self.epoch.load(.acquire);
            if (self.consumeSignal()) return;
        }
    }

    pub fn timedWait(self: *Condition, mutex: *Mutex, timeout_ns: u64) error{Timeout}!void {
        var epoch = self.epoch.load(.acquire);
        const prev_state = self.state.fetchAdd(.{ .waiters = 1, .signals = 0 }, .monotonic);
        std.debug.assert(prev_state.waiters < std.math.maxInt(u16));

        const deadline = nanoTimestamp() + @as(i128, timeout_ns);

        mutex.unlock();
        defer mutex.lock();

        while (true) {
            if (self.consumeSignal()) return;

            const now = nanoTimestamp();
            if (now >= deadline) {
                if (self.consumeSignalOrRemoveWaiter()) return;
                return error.Timeout;
            }

            const remaining_ns: u64 = @intCast(deadline - now);
            io().futexWaitTimeout(u32, &self.epoch.raw, epoch, .{
                .duration = .{
                    .raw = .fromNanoseconds(@intCast(remaining_ns)),
                    .clock = .awake,
                },
            }) catch |err| switch (err) {
                error.Canceled => unreachable,
            };
            epoch = self.epoch.load(.acquire);
        }
    }

    pub fn signal(self: *Condition) void {
        var prev_state = self.state.load(.monotonic);
        while (prev_state.waiters > prev_state.signals) {
            prev_state = self.state.cmpxchgWeak(prev_state, .{
                .waiters = prev_state.waiters,
                .signals = prev_state.signals + 1,
            }, .release, .monotonic) orelse {
                _ = self.epoch.fetchAdd(1, .release);
                io().futexWake(u32, &self.epoch.raw, 1);
                return;
            };
        }
    }

    pub fn broadcast(self: *Condition) void {
        var prev_state = self.state.load(.monotonic);
        while (prev_state.waiters > prev_state.signals) {
            const to_wake = prev_state.waiters - prev_state.signals;
            prev_state = self.state.cmpxchgWeak(prev_state, .{
                .waiters = prev_state.waiters,
                .signals = prev_state.waiters,
            }, .release, .monotonic) orelse {
                _ = self.epoch.fetchAdd(1, .release);
                io().futexWake(u32, &self.epoch.raw, to_wake);
                return;
            };
        }
    }

    fn consumeSignal(self: *Condition) bool {
        var prev_state = self.state.load(.monotonic);
        while (prev_state.signals > 0) {
            prev_state = self.state.cmpxchgWeak(prev_state, .{
                .waiters = prev_state.waiters - 1,
                .signals = prev_state.signals - 1,
            }, .acquire, .monotonic) orelse return true;
        }
        return false;
    }

    fn consumeSignalOrRemoveWaiter(self: *Condition) bool {
        var prev_state = self.state.load(.monotonic);
        while (true) {
            while (prev_state.signals > 0) {
                prev_state = self.state.cmpxchgWeak(prev_state, .{
                    .waiters = prev_state.waiters - 1,
                    .signals = prev_state.signals - 1,
                }, .acquire, .monotonic) orelse return true;
            }

            prev_state = self.state.cmpxchgWeak(prev_state, .{
                .waiters = prev_state.waiters - 1,
                .signals = prev_state.signals,
            }, .monotonic, .monotonic) orelse return false;
        }
    }
};
