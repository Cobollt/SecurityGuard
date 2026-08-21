using SecurityGuard.Core.Enums;

namespace SecurityGuard.Core.Models;

public sealed record SecurityDecisionRequest(
    Guid Id,
    SecurityModuleKind Module,
    SecurityEventType EventType,
    string Title,
    string Description,
    string? FilePath,
    string? ProcessName,
    IReadOnlyList<SecurityAction> AvailableActions,
    DateTimeOffset CreatedAtUtc,
    RuleMatchContext? RuleContext = null,
    string? Identity = null);