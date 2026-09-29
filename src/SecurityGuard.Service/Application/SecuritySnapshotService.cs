using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Models;

namespace SecurityGuard.Service.Application;

public sealed class SecuritySnapshotService
    : ISecuritySnapshotService
{
    private readonly IModuleRegistry _moduleRegistry;
    private readonly ISecurityEventRepository _eventRepository;
    private readonly IDecisionRequestRepository _decisionRepository;
    private readonly IQuarantineRepository _quarantineRepository;

    public SecuritySnapshotService(
        IModuleRegistry moduleRegistry,
        ISecurityEventRepository eventRepository,
        IDecisionRequestRepository decisionRepository,
        IQuarantineRepository quarantineRepository)
    {
        _moduleRegistry = moduleRegistry;
        _eventRepository = eventRepository;
        _decisionRepository = decisionRepository;
        _quarantineRepository = quarantineRepository;
    }

    public async Task<SecuritySnapshot> GetAsync(
        CancellationToken cancellationToken = default)
    {
        var recentEvents =
            await _eventRepository.GetRecentAsync(
                100,
                cancellationToken);

        var pendingRequests =
            await _decisionRepository.GetPendingAsync(
                cancellationToken);

        var quarantineCount =
            await _quarantineRepository.CountAsync(
                cancellationToken);

        return new SecuritySnapshot(
            _moduleRegistry.GetAll(),
            recentEvents,
            pendingRequests,
            quarantineCount,
            DateTimeOffset.UtcNow);
    }
}