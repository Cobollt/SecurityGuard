using SecurityGuard.Core.Models;

namespace SecurityGuard.UI.Services;

public interface ISecurityGuardClient
{
    Task<bool> PingAsync(
        CancellationToken cancellationToken = default);

    Task<SecuritySnapshot> GetSnapshotAsync(
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<SecurityRule>> GetRulesAsync(
        CancellationToken cancellationToken = default);

    Task SubmitDecisionAsync(
        SecurityDecision decision,
        CancellationToken cancellationToken = default);

    Task DeleteRuleAsync(
        Guid ruleId,
        CancellationToken cancellationToken = default);
}