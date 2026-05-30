const builtin = @import("builtin");
const humane_shell = @import("rendered_shell/humane_shell.zig");
const humane_shell_wire = @import("rendered_shell/humane_shell_wire.zig");
const journey_surface = @import("rendered_shell/journey_surface.zig");
const model = @import("rendered_shell/model.zig");
const production_journey = @import("rendered_shell/production_journey.zig");
const shell = @import("rendered_shell/shell.zig");
const task_shell_service = @import("rendered_shell/task_shell_service.zig");
const task_shell_wire = @import("rendered_shell/task_shell_wire.zig");

pub const Control = model.Control;
pub const JourneyControl = model.JourneyControl;
pub const Config = model.Config;
pub const JourneyConfig = model.JourneyConfig;

pub const HumaneShellControl = humane_shell.HumaneShellControl;
pub const HumaneShellKeyboardIntent = humane_shell.KeyboardIntent;
pub const HumaneShellOperation = humane_shell.HumaneShellOperation;
pub const HumaneShellControlState = humane_shell.ControlState;
pub const HumaneShellControlGuidance = humane_shell.ControlGuidance;
pub const HumaneShellStatus = humane_shell.HumaneShellStatus;
pub const HumaneShellRequest = humane_shell.HumaneShellRequest;
pub const HumaneShellResponse = humane_shell.HumaneShellResponse;
pub const HumaneShellAccessibilityProfile = humane_shell.AccessibilityProfile;
pub const HumaneShellConfig = humane_shell.HumaneShellConfig;
pub const HumaneShellState = humane_shell.HumaneShellState;
pub const HumaneShellCheckpointStore = humane_shell.HumaneShellCheckpointStore;
pub const HumaneShell = humane_shell.HumaneShell;
pub const humaneShellControlName = humane_shell.controlName;
pub const humaneShellStatusForError = humane_shell.statusForError;
pub const encodeHumaneShellRequest = humane_shell_wire.encodeRequest;
pub const decodeHumaneShellRequest = humane_shell_wire.decodeRequest;
pub const encodeHumaneShellResponse = humane_shell_wire.encodeResponse;
pub const decodeHumaneShellResponse = humane_shell_wire.decodeResponse;
pub const dispatchHumaneShellPayload = humane_shell_wire.dispatchPayload;
pub const HumaneShellWireError = humane_shell_wire.Error;

pub const TaskShellOperation = task_shell_wire.TaskShellOperation;
pub const TaskShellStatus = task_shell_wire.TaskShellStatus;
pub const TaskShellRequest = task_shell_wire.TaskShellRequest;
pub const TaskShellResponse = task_shell_wire.TaskShellResponse;
pub const encodeTaskShellRequest = task_shell_wire.encodeRequest;
pub const decodeTaskShellRequest = task_shell_wire.decodeRequest;
pub const encodeTaskShellResponse = task_shell_wire.encodeResponse;
pub const decodeTaskShellResponse = task_shell_wire.decodeResponse;

pub const Shell = shell.Shell;
pub const TaskShellState = task_shell_service.TaskShellState;
pub const TaskShellCheckpointStore = task_shell_service.TaskShellCheckpointStore;
pub const TaskShellService = task_shell_service.TaskShellService;
pub const JourneySurface = journey_surface.JourneySurface;
pub const ProductionJourneyControl = production_journey.ProductionJourneyControl;
pub const ProductionJourneyStatus = production_journey.ProductionJourneyStatus;
pub const ProductionJourneyConfig = production_journey.ProductionJourneyConfig;
pub const ProductionJourneyRequest = production_journey.ProductionJourneyRequest;
pub const ProductionJourneyResponse = production_journey.ProductionJourneyResponse;
pub const ProductionJourneyService = production_journey.ProductionJourneyService;

comptime {
    if (builtin.is_test) _ = @import("rendered_shell/tests.zig");
}
