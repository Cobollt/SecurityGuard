using SecurityGuard.Core.Enums;

namespace SecurityGuard.ArchiveGuard.Models;

public sealed record ArchiveGuardDecisionExecutionResult(
    bool Success,
    SecurityAction Action,
    string Message);