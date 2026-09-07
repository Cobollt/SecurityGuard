using SecurityGuard.Core.Enums;

namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IArchiveGuardAuditSink
{
    Task WriteAsync(
        SecurityEventType eventType,
        SecuritySeverity severity,
        string title,
        string details,
        CancellationToken cancellationToken = default);
}