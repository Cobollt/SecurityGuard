using SecurityGuard.Core.Enums;

namespace SecurityGuard.Core.Models;

public sealed record SecurityEvent(
    Guid Id,
    DateTimeOffset CreatedAtUtc,
    SecurityModuleKind Module,
    SecurityEventType Type,
    SecuritySeverity Severity,
    string Title,
    string Details,
    SecurityAction Action,
    Guid? CorrelationId)
{
    public static SecurityEvent Create(
        SecurityModuleKind module,
        SecurityEventType type,
        SecuritySeverity severity,
        string title,
        string details,
        SecurityAction action = SecurityAction.None,
        Guid? correlationId = null)
    {
        return new SecurityEvent(
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            module,
            type,
            severity,
            title,
            details,
            action,
            correlationId);
    }
}