using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.Infrastructure.Audit;

public sealed class AuditService
    : IAuditService
{
    private readonly ISecurityEventRepository _eventRepository;

    public AuditService(
        ISecurityEventRepository eventRepository)
    {
        _eventRepository = eventRepository;
    }

    public Task WriteAsync(
        SecurityModuleKind module,
        SecurityEventType type,
        SecuritySeverity severity,
        string title,
        string details,
        SecurityAction action = SecurityAction.None,
        Guid? correlationId = null,
        CancellationToken cancellationToken = default)
    {
        var securityEvent =
            SecurityEvent.Create(
                module,
                type,
                severity,
                title,
                details,
                action,
                correlationId);

        return _eventRepository.AddAsync(
            securityEvent,
            cancellationToken);
    }
}