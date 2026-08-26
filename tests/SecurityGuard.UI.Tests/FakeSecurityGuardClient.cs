using SecurityGuard.Core.Models;
using SecurityGuard.UI.Services;
using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.UI.Tests;

internal sealed class FakeSecurityGuardClient
    : ISecurityGuardClient
{
    public bool Connected { get; set; } = true;

    public TransferGuardSettings TransferGuardSettings { get; set; } =
    TransferGuardSettings.Default;

    public SecuritySnapshot Snapshot { get; set; } =
        new(
            [],
            [],
            [],
            0,
            DateTimeOffset.UtcNow);

    public IReadOnlyList<SecurityRule> Rules { get; set; } =
        [];

    public SecurityDecision? SubmittedDecision { get; private set; }

    public Guid? DeletedRuleId { get; private set; }

    public Exception? ExceptionToThrow { get; set; }

    public AlgorithmGuardSettings AlgorithmGuardSettings { get; set; } =
        AlgorithmGuardSettings.Default;

    public Task<bool> PingAsync(
        CancellationToken cancellationToken = default)
    {
        ThrowIfConfigured();

        return Task.FromResult(
            Connected);
    }

    public Task<SecuritySnapshot> GetSnapshotAsync(
        CancellationToken cancellationToken = default)
    {
        ThrowIfConfigured();

        return Task.FromResult(
            Snapshot);
    }

    public Task<IReadOnlyList<SecurityRule>> GetRulesAsync(
        CancellationToken cancellationToken = default)
    {
        ThrowIfConfigured();

        return Task.FromResult(
            Rules);
    }

    public Task SubmitDecisionAsync(
        SecurityDecision decision,
        CancellationToken cancellationToken = default)
    {
        ThrowIfConfigured();

        SubmittedDecision =
            decision;

        return Task.CompletedTask;
    }

    public Task DeleteRuleAsync(
        Guid ruleId,
        CancellationToken cancellationToken = default)
    {
        ThrowIfConfigured();

        DeletedRuleId =
            ruleId;

        Rules =
            Rules
                .Where(
                    rule =>
                        rule.Id != ruleId)
                .ToArray();

        return Task.CompletedTask;
    }

    public Task<AlgorithmGuardSettings> GetAlgorithmGuardSettingsAsync(
        CancellationToken cancellationToken = default)
    {
        ThrowIfConfigured();

        return Task.FromResult(
            AlgorithmGuardSettings);
    }

    public Task UpdateAlgorithmGuardSettingsAsync(
        AlgorithmGuardSettings settings,
        CancellationToken cancellationToken = default)
    {
        ThrowIfConfigured();

        AlgorithmGuardSettings =
            settings;

        return Task.CompletedTask;
    }

    public Task<TransferGuardSettings> GetTransferGuardSettingsAsync(
        CancellationToken cancellationToken = default)
    {
        ThrowIfConfigured();

        return Task.FromResult(
            TransferGuardSettings);
    }

    public Task UpdateTransferGuardSettingsAsync(
        TransferGuardSettings settings,
        CancellationToken cancellationToken = default)
    {
        ThrowIfConfigured();

        TransferGuardSettings =
            settings;

        return Task.CompletedTask;
    }

    private void ThrowIfConfigured()
    {
        if (ExceptionToThrow is not null)
        {
            throw ExceptionToThrow;
        }
    }
}