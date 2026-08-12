using SecurityGuard.Core.Models;

namespace SecurityGuard.Core.Contracts;

public interface ISecurityDecisionService
{
    Task ApplyAsync(
        SecurityDecision decision,
        CancellationToken cancellationToken = default);
}