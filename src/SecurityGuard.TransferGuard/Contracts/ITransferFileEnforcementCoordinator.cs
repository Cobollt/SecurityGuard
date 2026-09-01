using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Contracts;

public interface ITransferFileEnforcementCoordinator
{
    Task<TransferFileEnforcementResult> ApplyCandidateBlockAsync(
        Guid sourceSecurityRuleId,
        FileTransferCandidate candidate,
        CancellationToken cancellationToken = default);

    Task<TransferFileEnforcementResult> ApplyDecisionBlockAsync(
        Guid sourceSecurityRuleId,
        SecurityDecisionRequest request,
        CancellationToken cancellationToken = default);
}