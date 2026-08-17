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
        var eventsTask =
            _eventRepository.GetRecentAsync(
                100,
                cancellationToken);

        var decisionsTask =
            _decisionRepository.GetPendingAsync(
                cancellationToken);

        var quarantineTask =
            _quarantineRepository.CountAsync(
                cancellationToken);

        await Task.WhenAll(
            eventsTask,
            decisionsTask,
            quarantineTask);

        return new SecuritySnapshot(
            _moduleRegistry.GetAll(),
            await eventsTask,
            await decisionsTask,
            await quarantineTask,
            DateTimeOffset.UtcNow);
    }
}