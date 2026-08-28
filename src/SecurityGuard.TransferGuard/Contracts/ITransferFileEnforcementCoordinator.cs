using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Contracts;

public interface ITransferFileEnforcementCoordinator
{
    Task<TransferFileEnforcementResult> ApplyCandidateBlockAsync(
        FileTransferCandidate candidate,
        CancellationToken cancellationToken = default);

    Task<TransferFileEnforcementResult> ApplyDecisionBlockAsync(
        SecurityDecisionRequest request,
        CancellationToken cancellationToken = default);
}