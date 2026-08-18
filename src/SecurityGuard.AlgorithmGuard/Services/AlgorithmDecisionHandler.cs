using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.AlgorithmGuard.Services;

public sealed class AlgorithmDecisionHandler
    : ISecurityDecisionHandler
{
    private readonly IFileHashService _hashService;
    private readonly IRuleRepository _ruleRepository;
    private readonly IQuarantineService _quarantineService;
    private readonly IAlgorithmTemporaryDecisionStore _temporaryDecisionStore;

    public AlgorithmDecisionHandler(
        IFileHashService hashService,
        IRuleRepository ruleRepository,
        IQuarantineService quarantineService,
        IAlgorithmTemporaryDecisionStore temporaryDecisionStore)
    {
        _hashService =
            hashService;

        _ruleRepository =
            ruleRepository;

        _quarantineService =
            quarantineService;

        _temporaryDecisionStore =
            temporaryDecisionStore;
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
                await CreateRuleAsync(
                    request,
                    RuleDecision.Block,
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

    private async Task AllowOnceAsync(
        SecurityDecisionRequest request,
        CancellationToken cancellationToken)
    {
        var identity =
            await CreateIdentityAsync(
                request,
                cancellationToken);

        _temporaryDecisionStore.AllowOnce(
            identity);
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
        if (!string.IsNullOrWhiteSpace(
                request.FilePath) &&
            File.Exists(
                request.FilePath))
        {
            var hash =
                await _hashService.ComputeSha256Async(
                    request.FilePath,
                    cancellationToken);

            return new SecurityRule(
                Guid.NewGuid(),
                BuildRuleName(
                    request,
                    decision),
                SecurityModuleKind.AlgorithmGuard,
                decision,
                RuleScope.FileHash,
                hash,
                true,
                GetPriority(decision),
                DateTimeOffset.UtcNow,
                null);
        }

        if (!string.IsNullOrWhiteSpace(
                request.Description))
        {
            return new SecurityRule(
                Guid.NewGuid(),
                BuildRuleName(
                    request,
                    decision),
                SecurityModuleKind.AlgorithmGuard,
                decision,
                RuleScope.CommandLine,
                request.Description,
                true,
                GetPriority(decision),
                DateTimeOffset.UtcNow,
                null);
        }

        throw new InvalidOperationException(
            "Unable to create AlgorithmGuard rule.");
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
}