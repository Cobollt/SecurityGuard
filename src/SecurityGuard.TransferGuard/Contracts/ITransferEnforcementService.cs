using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Contracts;

public interface ITransferEnforcementService
{
    Task<TransferEnforcementResult> AddBlockAsync(
        TransferEnforcementRule rule,
        CancellationToken cancellationToken = default);

    Task RemoveBlockAsync(
        Guid securityRuleId,
        CancellationToken cancellationToken = default);

    Task<TransferEnforcementSnapshot> InspectAsync(
        CancellationToken cancellationToken = default);
}