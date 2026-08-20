using SecurityGuard.Core.Models;
using SecurityGuard.UI.Services;

namespace SecurityGuard.UI.Tests;

internal sealed class FakeSecurityGuardClient
    : ISecurityGuardClient
{
    public bool Connected { get; set; } = true;

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

    private void ThrowIfConfigured()
    {
        if (ExceptionToThrow is not null)
        {
            throw ExceptionToThrow;
        }
    }
}