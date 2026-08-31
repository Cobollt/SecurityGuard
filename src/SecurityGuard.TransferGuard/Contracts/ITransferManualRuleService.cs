using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Contracts;

public interface ITransferManualRuleService
{
    Task<SecurityRule> CreateAsync(
        TransferManualRuleRequest request,
        CancellationToken cancellationToken = default);
}