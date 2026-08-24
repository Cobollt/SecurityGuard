using SecurityGuard.Core.Models;
using SecurityGuard.AlgorithmGuard.Models;

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

    Task<AlgorithmGuardSettings> GetAlgorithmGuardSettingsAsync(
        CancellationToken cancellationToken = default);

    Task UpdateAlgorithmGuardSettingsAsync(
        AlgorithmGuardSettings settings,
        CancellationToken cancellationToken = default);
}