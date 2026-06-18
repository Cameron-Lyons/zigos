const std = @import("std");
const accelerator_scheduler = @import("../task/accelerator_scheduler.zig");

pub const Error = accelerator_scheduler.Error || error{
    CpuEngineUnsupported,
    MissingBrokerTask,
    MissingOwnerTask,
    MissingQueueGeneration,
    MissingHardwareOwnership,
    MissingCompletionInterrupt,
    StaleCompletionInterrupt,
};

pub const BrokeredAcceleratorQueueSession = struct {
    engine: accelerator_scheduler.Engine,
    broker_task_id: u64,
    owner_task_id: u64,
    generation: u32,
    completion_sequence: u64 = 0,
    completion_interrupts_observed: u32 = 0,
    hardware_queue_owned: bool = false,
    accepts_work: bool = false,

    pub fn init(
        engine: accelerator_scheduler.Engine,
        broker_task_id: u64,
        owner_task_id: u64,
        generation: u32,
    ) Error!BrokeredAcceleratorQueueSession {
        if (engine == .cpu) return error.CpuEngineUnsupported;
        if (broker_task_id == 0) return error.MissingBrokerTask;
        if (owner_task_id == 0) return error.MissingOwnerTask;
        if (generation == 0) return error.MissingQueueGeneration;
        return .{
            .engine = engine,
            .broker_task_id = broker_task_id,
            .owner_task_id = owner_task_id,
            .generation = generation,
        };
    }

    pub fn recordHardwareQueueOwnership(
        self: *BrokeredAcceleratorQueueSession,
        completion_sequence: u64,
        completion_interrupts_observed: u32,
    ) Error!void {
        if (completion_interrupts_observed == 0) return error.MissingCompletionInterrupt;
        self.completion_sequence = completion_sequence;
        self.completion_interrupts_observed = completion_interrupts_observed;
        self.hardware_queue_owned = true;
        self.accepts_work = true;
    }

    pub fn recordCompletionInterrupt(
        self: *BrokeredAcceleratorQueueSession,
        completion_sequence: u64,
    ) Error!void {
        if (!self.hardware_queue_owned) return error.MissingHardwareOwnership;
        if (completion_sequence <= self.completion_sequence) return error.StaleCompletionInterrupt;
        self.completion_sequence = completion_sequence;
        self.completion_interrupts_observed +|= 1;
    }

    pub fn event(self: BrokeredAcceleratorQueueSession) Error!accelerator_scheduler.BrokeredEngineQueueEvent {
        if (!self.hardware_queue_owned or !self.accepts_work) return error.MissingHardwareOwnership;
        if (self.completion_interrupts_observed == 0) return error.MissingCompletionInterrupt;
        return .{
            .engine = self.engine,
            .broker_task_id = self.broker_task_id,
            .owner_task_id = self.owner_task_id,
            .generation = self.generation,
            .completion_sequence = self.completion_sequence,
            .completion_interrupts_observed = self.completion_interrupts_observed,
            .accepts_work = self.accepts_work,
        };
    }

    pub fn publishQueueEvent(
        self: BrokeredAcceleratorQueueSession,
        scheduler: *accelerator_scheduler.Controller,
    ) Error!void {
        try scheduler.observeBrokeredEngineQueueEvent(try self.event());
    }
};

pub fn createQueueSession(
    engine: accelerator_scheduler.Engine,
    broker_task_id: u64,
    owner_task_id: u64,
    generation: u32,
) Error!BrokeredAcceleratorQueueSession {
    return BrokeredAcceleratorQueueSession.init(engine, broker_task_id, owner_task_id, generation);
}

test "accelerator driver task emits brokered queue ownership and completion events" {
    var scheduler = accelerator_scheduler.Controller.init();
    scheduler.configure(.{
        .gpu_available = true,
    });
    scheduler.requireBrokeredEngineQueues();

    var session = try createQueueSession(.gpu, 900, 91, 7);
    try std.testing.expectError(error.MissingHardwareOwnership, session.publishQueueEvent(&scheduler));
    try std.testing.expectError(error.MissingCompletionInterrupt, session.recordHardwareQueueOwnership(12, 0));

    try session.recordHardwareQueueOwnership(12, 1);
    try session.publishQueueEvent(&scheduler);
    try std.testing.expectEqual(@as(u32, 1), scheduler.brokeredQueueFor(.gpu).completion_interrupts_observed);

    const claim = try scheduler.claim(.{
        .task_id = 91,
        .request = .{
            .class = .foreground_interactive,
            .wants_gpu = true,
        },
        .require_accelerator = true,
    });
    try std.testing.expectEqual(accelerator_scheduler.Engine.gpu, claim.engine);
    try std.testing.expectError(error.QueueCompletionMissing, scheduler.releaseClaim(claim.id, null));
    try std.testing.expectError(error.StaleCompletionInterrupt, session.recordCompletionInterrupt(12));

    try session.recordCompletionInterrupt(13);
    try session.publishQueueEvent(&scheduler);
    try std.testing.expect(try scheduler.releaseClaim(claim.id, null));
    try std.testing.expectEqual(@as(u16, 0), scheduler.activeClaimCount());
}

test "accelerator driver task rejects invalid brokered queue sessions" {
    try std.testing.expectError(error.CpuEngineUnsupported, createQueueSession(.cpu, 900, 91, 1));
    try std.testing.expectError(error.MissingBrokerTask, createQueueSession(.npu, 0, 91, 1));
    try std.testing.expectError(error.MissingOwnerTask, createQueueSession(.media, 900, 0, 1));
    try std.testing.expectError(error.MissingQueueGeneration, createQueueSession(.gpu, 900, 91, 0));
}
