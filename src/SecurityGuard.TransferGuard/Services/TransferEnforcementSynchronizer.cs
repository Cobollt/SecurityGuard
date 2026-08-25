using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferEnforcementSynchronizer
    : ITransferEnforcementSynchronizer
{
    private readonly IRuleRepository _ruleRepository;
    private readonly ITransferEnforcementService _enforcementService;
    private readonly TransferEnforcementRuleFactory _ruleFactory;
    private readonly IAuditService _auditService;

    public TransferEnforcementSynchronizer(
        IRuleRepository ruleRepository,
        ITransferEnforcementService enforcementService,
        TransferEnforcementRuleFactory ruleFactory,
        IAuditService auditService)
    {
        _ruleRepository =
            ruleRepository;

        _enforcementService =
            enforcementService;

        _ruleFactory =
            ruleFactory;

        _auditService =
            auditService;
    }

    public async Task<TransferEnforcementSyncResult> SynchronizeAsync(
        CancellationToken cancellationToken = default)
    {
        var warnings =
            new List<string>();

        var added =
            0;

        var removed =
            0;

        TransferEnforcementSnapshot snapshot;

        try
        {
            snapshot =
                await _enforcementService.InspectAsync(
                    cancellationToken);
        }
        catch (Exception exception)
        {
            warnings.Add(
                $"Windows Firewall inspection failed: {exception.Message}");

            return await CompleteAsync(
                added,
                removed,
                warnings,
                cancellationToken);
        }

        var now =
            DateTimeOffset.UtcNow;

        var rules =
            await _ruleRepository.GetEnabledAsync(
                cancellationToken);

        var blockRules =
            rules
                .Where(
                    rule =>
                        rule.Module ==
                        SecurityModuleKind.TransferGuard)
                .Where(
                    rule =>
                        rule.Decision ==
                        RuleDecision.Block)
                .Where(
                    rule =>
                        rule.ExpiresAtUtc is null ||
                        rule.ExpiresAtUtc > now)
                .ToArray();

        var enforceable =
            new Dictionary<
                Guid,
                TransferEnforcementRule>();

        foreach (var rule in blockRules)
        {
            if (_ruleFactory.TryCreate(
                    rule,
                    out var enforcementRule,
                    out var error) &&
                enforcementRule is not null)
            {
                enforceable[rule.Id] =
                    enforcementRule;
            }
            else
            {
                warnings.Add(
                    $"Rule {rule.Id} cannot be enforced by Windows Firewall: {error}");
            }
        }

        var stale =
            snapshot.PersistentManagedRuleIds
                .Where(
                    id =>
                        !enforceable.ContainsKey(
                            id))
                .ToArray();

        foreach (var id in stale)
        {
            try
            {
                await _enforcementService.RemoveBlockAsync(
                    id,
                    cancellationToken);

                removed++;
            }
            catch (Exception exception)
            {
                warnings.Add(
                    $"Unable to remove stale Firewall rule {id}: {exception.Message}");
            }
        }

        foreach (var item in enforceable)
        {
            if (snapshot.PersistentManagedRuleIds.Contains(
                    item.Key))
            {
                continue;
            }

            try
            {
                var result =
                    await _enforcementService.AddBlockAsync(
                        item.Value,
                        cancellationToken);

                if (result.Applied)
                {
                    added++;
                }
                else
                {
                    warnings.Add(
                        $"Unable to restore Firewall rule {item.Key}: {result.Message}");
                }
            }
            catch (Exception exception)
            {
                warnings.Add(
                    $"Unable to restore Firewall rule {item.Key}: {exception.Message}");
            }
        }

        try
        {
            var finalSnapshot =
                await _enforcementService.InspectAsync(
                    cancellationToken);

            foreach (var id in
                     enforceable.Keys)
            {
                if (!finalSnapshot.PersistentManagedRuleIds.Contains(
                        id))
                {
                    warnings.Add(
                        $"Rule {id} is missing from Windows Firewall PersistentStore.");

                    continue;
                }

                if (!finalSnapshot.ActiveManagedRuleIds.Contains(
                        id))
                {
                    warnings.Add(
                        $"Rule {id} is not active in the effective Windows Firewall policy.");
                }
            }
        }
        catch (Exception exception)
        {
            warnings.Add(
                $"Final Windows Firewall inspection failed: {exception.Message}");
        }

        return await CompleteAsync(
            added,
            removed,
            warnings,
            cancellationToken);
    }

    private async Task<TransferEnforcementSyncResult> CompleteAsync(
        int added,
        int removed,
        IReadOnlyList<string> warnings,
        CancellationToken cancellationToken)
    {
        var healthy =
            warnings.Count == 0;

        await _auditService.WriteAsync(
            SecurityModuleKind.TransferGuard,
            SecurityEventType.System,
            healthy
                ? SecuritySeverity.Info
                : SecuritySeverity.Medium,
            healthy
                ? "TransferGuard enforcement synchronized"
                : "TransferGuard enforcement synchronization warning",
            healthy
                ? "SQLite rules and Windows Firewall are synchronized."
                : string.Join(
                    Environment.NewLine,
                    warnings),
            cancellationToken:
                cancellationToken);

        return new TransferEnforcementSyncResult(
            added,
            removed,
            healthy,
            warnings);
    }
}