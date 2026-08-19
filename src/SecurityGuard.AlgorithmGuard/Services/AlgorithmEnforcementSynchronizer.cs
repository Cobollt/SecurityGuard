using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Enums;
using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.AlgorithmGuard.Services;

public sealed class AlgorithmEnforcementSynchronizer
{
    private readonly IRuleRepository _ruleRepository;
    private readonly IProtectedObjectRepository _protectedObjectRepository;
    private readonly IAlgorithmEnforcementService _enforcementService;
    private readonly IAuditService _auditService;

    public AlgorithmEnforcementSynchronizer(
        IRuleRepository ruleRepository,
        IProtectedObjectRepository protectedObjectRepository,
        IAlgorithmEnforcementService enforcementService,
        IAuditService auditService)
    {
        _ruleRepository =
            ruleRepository;

        _protectedObjectRepository =
            protectedObjectRepository;

        _enforcementService =
            enforcementService;

        _auditService =
            auditService;
    }

    public async Task<AlgorithmEnforcementSyncResult> SynchronizeAsync(
        CancellationToken cancellationToken = default)
    {
        var warnings =
            new List<string>();

        var added = 0;
        var removed = 0;

        AlgorithmEnforcementSnapshot snapshot;

        try
        {
            snapshot =
                await _enforcementService.InspectAsync(
                    cancellationToken);
        }
        catch (Exception exception)
        {
            warnings.Add(
                $"AppLocker inspection failed: {exception.Message}");

            await WriteResultAsync(
                false,
                warnings,
                cancellationToken);

            return new AlgorithmEnforcementSyncResult(
                0,
                0,
                false,
                warnings);
        }

        var rules =
            await _ruleRepository.GetEnabledAsync(
                cancellationToken);

        var blockRules =
            rules
                .Where(
                    rule =>
                        rule.Module ==
                        SecurityModuleKind.AlgorithmGuard)
                .Where(
                    rule =>
                        rule.Decision ==
                        RuleDecision.Block)
                .Where(
                    rule =>
                        rule.Scope ==
                        RuleScope.FileHash)
                .ToArray();

        var databaseRuleIds =
            blockRules
                .Select(rule => rule.Id)
                .ToHashSet();

        var staleIds =
            snapshot.LocalManagedRuleIds
                .Where(
                    id =>
                        !databaseRuleIds.Contains(id))
                .ToArray();

        foreach (var staleId in staleIds)
        {
            try
            {
                await _enforcementService.RemoveBlockAsync(
                    staleId,
                    cancellationToken);

                removed++;
            }
            catch (Exception exception)
            {
                warnings.Add(
                    $"Unable to remove stale AppLocker rule {staleId}: {exception.Message}");
            }
        }

        foreach (var rule in blockRules)
        {
            if (snapshot.LocalManagedRuleIds.Contains(
                    rule.Id))
            {
                continue;
            }

            var protectedObject =
                await _protectedObjectRepository.FindByHashAsync(
                    rule.Value,
                    cancellationToken);

            if (protectedObject is null)
            {
                warnings.Add(
                    $"Protected object for rule {rule.Id} was not found.");

                continue;
            }

            var level =
                _enforcementService.GetLevel(
                    protectedObject.Path);

            if (level ==
                AlgorithmEnforcementLevel.Unsupported)
            {
                continue;
            }

            if (!File.Exists(
                    protectedObject.Path))
            {
                warnings.Add(
                    $"Script for rule {rule.Id} is currently unavailable: {protectedObject.Path}");

                continue;
            }

            try
            {
                var result =
                    await _enforcementService.AddBlockAsync(
                        rule.Id,
                        protectedObject.Path,
                        cancellationToken);

                if (result.Applied)
                {
                    added++;
                }
                else
                {
                    warnings.Add(
                        $"Unable to restore AppLocker rule {rule.Id}: {result.Message}");
                }
            }
            catch (Exception exception)
            {
                warnings.Add(
                    $"Unable to restore AppLocker rule {rule.Id}: {exception.Message}");
            }
        }

        AlgorithmEnforcementSnapshot finalSnapshot;

        try
        {
            finalSnapshot =
                await _enforcementService.InspectAsync(
                    cancellationToken);
        }
        catch (Exception exception)
        {
            warnings.Add(
                $"Final AppLocker inspection failed: {exception.Message}");

            await WriteResultAsync(
                false,
                warnings,
                cancellationToken);

            return new AlgorithmEnforcementSyncResult(
                added,
                removed,
                false,
                warnings);
        }

        foreach (var rule in blockRules)
        {
            var protectedObject =
                await _protectedObjectRepository.FindByHashAsync(
                    rule.Value,
                    cancellationToken);

            if (protectedObject is null)
            {
                continue;
            }

            if (_enforcementService.GetLevel(
                    protectedObject.Path) ==
                AlgorithmEnforcementLevel.Unsupported)
            {
                continue;
            }

            if (!finalSnapshot.LocalManagedRuleIds.Contains(
                    rule.Id))
            {
                warnings.Add(
                    $"Rule {rule.Id} is missing from local AppLocker policy.");

                continue;
            }

            if (!finalSnapshot.EffectiveManagedRuleIds.Contains(
                    rule.Id))
            {
                warnings.Add(
                    $"Rule {rule.Id} is not present in effective AppLocker policy.");
            }
        }

        if (finalSnapshot.ManagedBaselinePresent &&
            finalSnapshot.UnmanagedScriptRulesPresent)
        {
            warnings.Add(
                "SecurityGuard baseline and unmanaged local Script rules coexist.");
        }

        var healthy =
            warnings.Count == 0;

        await WriteResultAsync(
            healthy,
            warnings,
            cancellationToken);

        return new AlgorithmEnforcementSyncResult(
            added,
            removed,
            healthy,
            warnings);
    }

    private Task WriteResultAsync(
        bool healthy,
        IReadOnlyList<string> warnings,
        CancellationToken cancellationToken)
    {
        var severity =
            healthy
                ? SecuritySeverity.Info
                : SecuritySeverity.Medium;

        var title =
            healthy
                ? "AlgorithmGuard enforcement synchronized"
                : "AlgorithmGuard enforcement synchronization warning";

        var details =
            healthy
                ? "SQLite rules and AppLocker enforcement are synchronized."
                : string.Join(
                    Environment.NewLine,
                    warnings);

        return _auditService.WriteAsync(
            SecurityModuleKind.AlgorithmGuard,
            SecurityEventType.System,
            severity,
            title,
            details,
            cancellationToken: cancellationToken);
    }
}