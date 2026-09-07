using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.Service.Application;

public sealed class ArchiveGuardAuditSink
    : IArchiveGuardAuditSink
{
    private readonly IAuditService _auditService;

    public ArchiveGuardAuditSink(
        IAuditService auditService)
    {
        _auditService =
            auditService;
    }

    public Task WriteAsync(
        SecurityEventType eventType,
        SecuritySeverity severity,
        string title,
        string details,
        CancellationToken cancellationToken = default)
    {
        return _auditService.WriteAsync(
            SecurityModuleKind.ArchiveGuard,
            eventType,
            severity,
            title,
            details,
            cancellationToken:
                cancellationToken);
    }
}