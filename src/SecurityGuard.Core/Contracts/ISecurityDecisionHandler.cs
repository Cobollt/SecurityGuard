using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.Core.Contracts;

public interface ISecurityDecisionHandler
{
    SecurityModuleKind Module { get; }

    Task HandleAsync(
        SecurityDecisionRequest request,
        SecurityDecision decision,
        CancellationToken cancellationToken = default);
}