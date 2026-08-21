using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.AlgorithmGuard.Configuration;

namespace SecurityGuard.AlgorithmGuard.Services;

public sealed class AlgorithmDecisionHandler
    : ISecurityDecisionHandler
{
    private readonly IFileHashService _hashService;
    private readonly IRuleRepository _ruleRepository;
    private readonly IQuarantineService _quarantineService;
    private readonly IAlgorithmTemporaryDecisionStore _temporaryDecisionStore;
    private readonly IAlgorithmEnforcementService _enforcementService;
    private readonly AlgorithmGuardOptions _options;

    public AlgorithmDecisionHandler(
        IFileHashService hashService,
        IRuleRepository ruleRepository,
        IQuarantineService quarantineService,
        IAlgorithmTemporaryDecisionStore temporaryDecisionStore,
        IAlgorithmEnforcementService enforcementService,
        AlgorithmGuardOptions options)
    {
        _hashService =
            hashService;

        _ruleRepository =
            ruleRepository;

        _quarantineService =
            quarantineService;

        _temporaryDecisionStore =
            temporaryDecisionStore;

        _enforcementService =
            enforcementService;

        _options =
            options;
    }

    public SecurityModuleKind Module =>
        SecurityModuleKind.AlgorithmGuard;

    public async Task HandleAsync(
        SecurityDecisionRequest request,
        SecurityDecision decision,
        CancellationToken cancellationToken = default)
    {
        switch (decision.Action)
        {
            case SecurityAction.AllowOnce:
                await AllowOnceAsync(
                    request,
                    cancellationToken);

                break;

            case SecurityAction.Allow:
                await CreateRuleAsync(
                    request,
                    RuleDecision.Allow,
                    cancellationToken);

                break;

            case SecurityAction.Block:
                await BlockAsync(
                    request,
                    cancellationToken);

                break;

            case SecurityAction.Quarantine:
                await QuarantineAsync(
                    request,
                    cancellationToken);

                break;

            case SecurityAction.Delete:
                Delete(request);
                break;

            default:
                throw new InvalidOperationException(
                    $"Unsupported AlgorithmGuard action: {decision.Action}");
        }
    }

    private async Task BlockAsync(
        SecurityDecisionRequest request,
        CancellationToken cancellationToken)
    {
        var rule =
            await BuildRuleAsync(
                request,
                RuleDecision.Block,
                cancellationToken);

        if (!string.IsNullOrWhiteSpace(
                request.FilePath))
        {
            var level =
                _enforcementService.GetLevel(
                    request.FilePath);

            if (level !=
                Enums.AlgorithmEnforcementLevel.Unsupported)
            {
                var result =
                    await _enforcementService.AddBlockAsync(
                        rule.Id,
                        request.FilePath,
                        cancellationToken);

                if (!result.Applied)
                {
                    throw new InvalidOperationException(
                        result.Message);
                }
            }
        }

        await _ruleRepository.UpsertAsync(
            rule,
            cancellationToken);
        }

    private async Task AllowOnceAsync(
        SecurityDecisionRequest request,
        CancellationToken cancellationToken)
    {
        var identity =
            request.Identity;

        if (string.IsNullOrWhiteSpace(
                identity))
        {
            identity =
                await CreateLegacyIdentityAsync(
                    request,
                    cancellationToken);
        }

        _temporaryDecisionStore.AllowOnce(
            identity,
            DateTimeOffset.UtcNow +
            _options.AllowOnceLifetime);
    }

    private async Task CreateRuleAsync(
        SecurityDecisionRequest request,
        RuleDecision decision,
        CancellationToken cancellationToken)
    {
        var rule =
            await BuildRuleAsync(
                request,
                decision,
                cancellationToken);

        await _ruleRepository.UpsertAsync(
            rule,
            cancellationToken);
    }

    private async Task<SecurityRule> BuildRuleAsync(
        SecurityDecisionRequest request,
        RuleDecision decision,
        CancellationToken cancellationToken)
    {
        RuleScope primaryScope;
        string primaryValue;

        if (!string.IsNullOrWhiteSpace(
                request.FilePath) &&
            File.Exists(
                request.FilePath))
        {
            primaryScope =
                RuleScope.FileHash;

            primaryValue =
                await _hashService.ComputeSha256Async(
                    request.FilePath,
                    cancellationToken);
        }
        else
        {
            var commandLine =
                request.RuleContext?.CommandLine ??
                request.Description;

            if (string.IsNullOrWhiteSpace(
                    commandLine))
            {
                throw new InvalidOperationException(
                    "Unable to create AlgorithmGuard rule.");
            }

            primaryScope =
                RuleScope.CommandLine;

            primaryValue =
                commandLine;
        }

        var conditions =
            decision == RuleDecision.Allow
                ? BuildAllowConditions(
                    request,
                    primaryScope,
                    primaryValue)
                : [];

        return new SecurityRule(
            Guid.NewGuid(),
            BuildRuleName(
                request,
                decision),
            SecurityModuleKind.AlgorithmGuard,
            decision,
            primaryScope,
            primaryValue,
            true,
            GetPriority(
                decision),
            DateTimeOffset.UtcNow,
            null,
            conditions);
    }

        private static IReadOnlyList<SecurityRuleCondition> BuildAllowConditions(
        SecurityDecisionRequest request,
        RuleScope primaryScope,
        string primaryValue)
    {
        if (request.RuleContext is null)
        {
            return [];
        }

        var context =
            request.RuleContext;

        var conditions =
            new List<SecurityRuleCondition>();

        AddCondition(
            conditions,
            RuleScope.Process,
            context.Process,
            primaryScope,
            primaryValue);

        AddCondition(
            conditions,
            RuleScope.UserName,
            context.UserName,
            primaryScope,
            primaryValue);

        if (!string.IsNullOrWhiteSpace(
                context.ParentProcessPath))
        {
            AddCondition(
                conditions,
                RuleScope.ParentProcessPath,
                context.ParentProcessPath,
                primaryScope,
                primaryValue);
        }
        else
        {
            AddCondition(
                conditions,
                RuleScope.ParentProcess,
                context.ParentProcess,
                primaryScope,
                primaryValue);
        }

        AddCondition(
            conditions,
            RuleScope.ProcessPublisher,
            context.ProcessPublisher,
            primaryScope,
            primaryValue);

        return conditions;
    }

        private static void AddCondition(
        ICollection<SecurityRuleCondition> conditions,
        RuleScope scope,
        string? value,
        RuleScope primaryScope,
        string primaryValue)
    {
        if (string.IsNullOrWhiteSpace(
                value))
        {
            return;
        }

        if (scope == primaryScope &&
            string.Equals(
                value,
                primaryValue,
                StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        conditions.Add(
            new SecurityRuleCondition(
                scope,
                value));
    }
    private async Task<string> CreateIdentityAsync(
        SecurityDecisionRequest request,
        CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(
                request.FilePath) &&
            File.Exists(
                request.FilePath))
        {
            var hash =
                await _hashService.ComputeSha256Async(
                    request.FilePath,
                    cancellationToken);

            var attempt =
                new AlgorithmExecutionAttempt(
                    Guid.NewGuid(),
                    0,
                    null,
                    request.ProcessName ?? string.Empty,
                    null,
                    request.Description,
                    Enums.InterpreterKind.PowerShell,
                    Enums.AlgorithmInvocationType.ScriptFile,
                    request.FilePath,
                    hash,
                    DateTimeOffset.UtcNow);

            return AlgorithmExecutionIdentity.Create(
                attempt);
        }

        return string.Join(
            ":",
            "COMMAND",
            request.ProcessName ?? string.Empty,
            request.Description);
    }

    private async Task QuarantineAsync(
        SecurityDecisionRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(
                request.FilePath))
        {
            throw new InvalidOperationException(
                "This execution has no script file.");
        }

        await _quarantineService.QuarantineAsync(
            request.FilePath,
            SecurityModuleKind.AlgorithmGuard,
            "Blocked by AlgorithmGuard decision",
            cancellationToken);
    }

    private static void Delete(
        SecurityDecisionRequest request)
    {
        if (string.IsNullOrWhiteSpace(
                request.FilePath))
        {
            throw new InvalidOperationException(
                "This execution has no script file.");
        }

        if (!File.Exists(
                request.FilePath))
        {
            throw new FileNotFoundException(
                "Script file was not found.",
                request.FilePath);
        }

        File.Delete(
            request.FilePath);
    }

    private static string BuildRuleName(
        SecurityDecisionRequest request,
        RuleDecision decision)
    {
        return $"{decision}: {request.ProcessName ?? "Algorithm"}";
    }

    private static int GetPriority(
        RuleDecision decision)
    {
        return decision switch
        {
            RuleDecision.Block => 200,
            RuleDecision.Allow => 100,
            _ => 0
        };
    }

    private async Task<string> CreateLegacyIdentityAsync(
        SecurityDecisionRequest request,
        CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(
                request.FilePath) &&
            File.Exists(
                request.FilePath))
        {
            var hash =
                await _hashService.ComputeSha256Async(
                    request.FilePath,
                    cancellationToken);

            return $"LEGACY-HASH:{hash}";
        }

        return string.Join(
            ":",
            "LEGACY-COMMAND",
            request.ProcessName ?? string.Empty,
            request.Description);
    }
}