using SecurityGuard.Core.Enums;

namespace SecurityGuard.Core.Contracts;

public interface IAuditService
{
    Task WriteAsync(
        SecurityModuleKind module,
        SecurityEventType type,
        SecuritySeverity severity,
        string title,
        string details,
        SecurityAction action = SecurityAction.None,
        Guid? correlationId = null,
        CancellationToken cancellationToken = default);
}