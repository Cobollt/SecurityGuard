using System.Net;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferManualRuleService
    : ITransferManualRuleService
{
    private static readonly HashSet<RuleScope> NetworkScopes =
    [
        RuleScope.Process,
        RuleScope.ProcessPath,
        RuleScope.RemoteAddress,
        RuleScope.RemotePort,
        RuleScope.Protocol
    ];

    private static readonly HashSet<RuleScope> FileScopes =
    [
        RuleScope.FileHash,
        RuleScope.FilePath,
        RuleScope.FileName,
        RuleScope.FileExtension,
        RuleScope.FileCategory,
        RuleScope.Process,
        RuleScope.ProcessPath,
        RuleScope.RemoteAddress,
        RuleScope.RemotePort,
        RuleScope.Protocol
    ];

    private static readonly HashSet<RuleScope> FileIdentityScopes =
    [
        RuleScope.FileHash,
        RuleScope.FilePath,
        RuleScope.FileName,
        RuleScope.FileExtension,
        RuleScope.FileCategory
    ];

    private readonly IRuleRepository _ruleRepository;
    private readonly ITransferPathNormalizer _pathNormalizer;
    private readonly ITransferEnforcementService _enforcementService;
    private readonly TransferEnforcementRuleFactory _enforcementRuleFactory;
    private readonly ITransferGuardRuntimeController _runtimeController;

    public TransferManualRuleService(
        IRuleRepository ruleRepository,
        ITransferPathNormalizer pathNormalizer,
        ITransferEnforcementService enforcementService,
        TransferEnforcementRuleFactory enforcementRuleFactory,
        ITransferGuardRuntimeController runtimeController)
    {
        _ruleRepository =
            ruleRepository;

        _pathNormalizer =
            pathNormalizer;

        _enforcementService =
            enforcementService;

        _enforcementRuleFactory =
            enforcementRuleFactory;

        _runtimeController =
            runtimeController;
    }

    public async Task<SecurityRule> CreateAsync(
        TransferManualRuleRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            request);

        var conditions =
            ValidateAndNormalize(
                request);

        var primary =
            conditions[0];

        var additional =
            new List<SecurityRuleCondition>
            {
                new(
                    RuleScope.TransferActivityKind,
                    request.ActivityKind.ToString())
            };

        additional.AddRange(
            conditions
                .Skip(1)
                .Select(
                    condition =>
                        new SecurityRuleCondition(
                            condition.Scope,
                            condition.Value)));

        var rule =
            new SecurityRule(
                Guid.NewGuid(),
                request.Name.Trim(),
                SecurityModuleKind.TransferGuard,
                request.Decision,
                primary.Scope,
                primary.Value,
                true,
                request.Priority,
                DateTimeOffset.UtcNow,
                request.ExpiresAtUtc?.ToUniversalTime(),
                additional);

        if (request.ActivityKind !=
                TransferActivityKind.NetworkConnection ||
            request.Decision !=
                RuleDecision.Block)
        {
            await _ruleRepository.UpsertAsync(
                rule,
                cancellationToken);

            return rule;
        }

        await CreateNetworkBlockAsync(
            rule,
            cancellationToken);

        return rule;
    }

    private async Task CreateNetworkBlockAsync(
        SecurityRule rule,
        CancellationToken cancellationToken)
    {
        var settings =
            _runtimeController.CurrentSettings;

        if (!settings.Enabled ||
            settings.Mode ==
            TransferGuardMode.Monitor)
        {
            await _ruleRepository.UpsertAsync(
                rule,
                cancellationToken);

            return;
        }

        if (!_enforcementRuleFactory.TryCreate(
                rule,
                out var enforcementRule,
                out var error) ||
            enforcementRule is null)
        {
            var message =
                error ??
                "Unable to create Windows Firewall projection.";

            await HandleEnforcementFailureAsync(
                rule,
                message,
                settings,
                cancellationToken);

            return;
        }

        try
        {
            var result =
                await _enforcementService.AddBlockAsync(
                    enforcementRule,
                    cancellationToken);

            if (!result.Applied)
            {
                throw new InvalidOperationException(
                    result.Message);
            }
        }
        catch (Exception exception)
        {
            await HandleEnforcementFailureAsync(
                rule,
                exception.Message,
                settings,
                cancellationToken);

            return;
        }

        try
        {
            await _ruleRepository.UpsertAsync(
                rule,
                cancellationToken);
        }
        catch
        {
            try
            {
                await _enforcementService.RemoveBlockAsync(
                    rule.Id,
                    cancellationToken);
            }
            catch
            {
            }

            throw;
        }
    }

    private async Task HandleEnforcementFailureAsync(
        SecurityRule rule,
        string message,
        TransferGuardSettings settings,
        CancellationToken cancellationToken)
    {
        await _runtimeController.ReportEnforcementFailureAsync(
            message,
            cancellationToken);

        if (settings.FailurePolicy ==
            TransferEnforcementFailurePolicy.FailClosed)
        {
            throw new InvalidOperationException(
                message);
        }

        await _ruleRepository.UpsertAsync(
            rule,
            cancellationToken);
    }

    private IReadOnlyList<TransferManualRuleCondition> ValidateAndNormalize(
        TransferManualRuleRequest request)
    {
        if (string.IsNullOrWhiteSpace(
                request.Name))
        {
            throw new InvalidOperationException(
                "Rule name is required.");
        }

        if (request.Priority is < 0 or > 1000)
        {
            throw new InvalidOperationException(
                "Priority must be between 0 and 1000.");
        }

        if (request.ExpiresAtUtc is not null &&
            request.ExpiresAtUtc <=
            DateTimeOffset.UtcNow)
        {
            throw new InvalidOperationException(
                "Expiration must be in the future.");
        }

        if (request.Conditions is null ||
            request.Conditions.Count == 0)
        {
            throw new InvalidOperationException(
                "At least one rule condition is required.");
        }

        var allowedScopes =
            request.ActivityKind ==
            TransferActivityKind.NetworkConnection
                ? NetworkScopes
                : FileScopes;

        var normalized =
            new List<TransferManualRuleCondition>();

        var usedScopes =
            new HashSet<RuleScope>();

        foreach (var condition in
                 request.Conditions)
        {
            if (!allowedScopes.Contains(
                    condition.Scope))
            {
                throw new InvalidOperationException(
                    $"Scope {condition.Scope} is not supported for {request.ActivityKind}.");
            }

            if (!usedScopes.Add(
                    condition.Scope))
            {
                throw new InvalidOperationException(
                    $"Scope {condition.Scope} is specified more than once.");
            }

            normalized.Add(
                NormalizeCondition(
                    condition));
        }

        if (request.ActivityKind ==
                TransferActivityKind.FileTransfer &&
            !normalized.Any(
                condition =>
                    FileIdentityScopes.Contains(
                        condition.Scope)))
        {
            throw new InvalidOperationException(
                "FileTransfer rule requires at least one file condition.");
        }

        if (request.ActivityKind ==
                TransferActivityKind.NetworkConnection &&
            request.Decision ==
                RuleDecision.Block)
        {
            RequireScope(
                normalized,
                RuleScope.ProcessPath);

            RequireScope(
                normalized,
                RuleScope.RemoteAddress);

            RequireScope(
                normalized,
                RuleScope.RemotePort);

            RequireScope(
                normalized,
                RuleScope.Protocol);
        }

        return normalized;
    }

    private TransferManualRuleCondition NormalizeCondition(
        TransferManualRuleCondition condition)
    {
        if (string.IsNullOrWhiteSpace(
                condition.Value))
        {
            throw new InvalidOperationException(
                $"Value for {condition.Scope} is required.");
        }

        var value =
            condition.Value.Trim();

        switch (condition.Scope)
        {
            case RuleScope.ProcessPath:
            {
                var normalized =
                    _pathNormalizer.Normalize(
                        value);

                if (string.IsNullOrWhiteSpace(
                        normalized) ||
                    !Path.IsPathFullyQualified(
                        normalized))
                {
                    throw new InvalidOperationException(
                        "ProcessPath must be a fully qualified path.");
                }

                value =
                    normalized;

                break;
            }

            case RuleScope.FilePath:
            {
                value =
                    Path.GetFullPath(
                        value);

                break;
            }

            case RuleScope.FileHash:
            {
                value =
                    value.ToUpperInvariant();

                if (value.Length != 64 ||
                    value.Any(
                        character =>
                            !Uri.IsHexDigit(
                                character)))
                {
                    throw new InvalidOperationException(
                        "FileHash must be a SHA-256 value.");
                }

                break;
            }

            case RuleScope.FileExtension:
            {
                if (!value.StartsWith(
                        '.'))
                {
                    value =
                        "." + value;
                }

                value =
                    value.ToLowerInvariant();

                break;
            }

            case RuleScope.FileCategory:
            {
                if (!Enum.TryParse<TransferFileCategory>(
                        value,
                        true,
                        out var category))
                {
                    throw new InvalidOperationException(
                        "Unknown file category.");
                }

                value =
                    category.ToString();

                break;
            }

            case RuleScope.RemoteAddress:
            {
                if (!IPAddress.TryParse(
                        value,
                        out var address))
                {
                    throw new InvalidOperationException(
                        "RemoteAddress must be a valid IP address.");
                }

                value =
                    address.ToString();

                break;
            }

            case RuleScope.RemotePort:
            {
                if (!int.TryParse(
                        value,
                        out var port) ||
                    port is < 1 or > 65535)
                {
                    throw new InvalidOperationException(
                        "RemotePort must be between 1 and 65535.");
                }

                value =
                    port.ToString();

                break;
            }

            case RuleScope.Protocol:
            {
                if (!Enum.TryParse<TransferProtocol>(
                        value,
                        true,
                        out var protocol))
                {
                    throw new InvalidOperationException(
                        "Protocol must be Tcp or Udp.");
                }

                value =
                    protocol.ToString();

                break;
            }
        }

        return new TransferManualRuleCondition(
            condition.Scope,
            value);
    }

    private static void RequireScope(
        IEnumerable<TransferManualRuleCondition> conditions,
        RuleScope scope)
    {
        if (!conditions.Any(
                condition =>
                    condition.Scope ==
                    scope))
        {
            throw new InvalidOperationException(
                $"Network Block rule requires {scope}.");
        }
    }
}