using SecurityGuard.Core.Enums;

namespace SecurityGuard.Core.Models;

public sealed record ModuleStatus(
    SecurityModuleKind Module,
    ModuleOperationalState State,
    string Message,
    DateTimeOffset UpdatedAtUtc);