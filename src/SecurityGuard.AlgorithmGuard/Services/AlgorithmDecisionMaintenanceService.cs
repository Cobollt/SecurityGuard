using SecurityGuard.AlgorithmGuard.Configuration;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.AlgorithmGuard.Services;

public sealed class AlgorithmDecisionMaintenanceService
{
    private readonly IDecisionRequestRepository _decisionRepository;
    private readonly IAuditService _auditService;
    private readonly AlgorithmGuardOptions _options;

    public AlgorithmDecisionMaintenanceService(
        IDecisionRequestRepository decisionRepository,
        IAuditService auditService,
        AlgorithmGuardOptions options)
    {
        _decisionRepository =
            decisionRepository;

        _auditService =
            auditService;

        _options =
            options;
    }

    public async Task<int> CleanupAsync(
        CancellationToken cancellationToken = default)
    {
        var cutoff =
            DateTimeOffset.UtcNow -
            _options.PendingDecisionLifetime;

        var removed =
            await _decisionRepository.RemoveOlderThanAsync(
                cutoff,
                cancellationToken);

        if (removed > 0)
        {
            await _auditService.WriteAsync(
                SecurityModuleKind.AlgorithmGuard,
                SecurityEventType.System,
                SecuritySeverity.Info,
                "Expired decisions removed",
                $"Removed pending decisions: {removed}",
                cancellationToken: cancellationToken);
        }

        return removed;
    }
}