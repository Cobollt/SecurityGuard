using System.Net;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Configuration;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferFileEnforcementCoordinator
    : ITransferFileEnforcementCoordinator
{
    private readonly ITransferTemporaryEnforcementService _temporaryEnforcement;
    private readonly ITransferGuardRuntimeState _runtimeState;
    private readonly ITransferPathNormalizer _pathNormalizer;
    private readonly IModuleRegistry _moduleRegistry;
    private readonly TransferGuardOptions _options;

    public TransferFileEnforcementCoordinator(
        ITransferTemporaryEnforcementService temporaryEnforcement,
        ITransferGuardRuntimeState runtimeState,
        ITransferPathNormalizer pathNormalizer,
        IModuleRegistry moduleRegistry,
        TransferGuardOptions options)
    {
        _temporaryEnforcement =
            temporaryEnforcement;

        _runtimeState =
            runtimeState;

        _pathNormalizer =
            pathNormalizer;

        _moduleRegistry =
            moduleRegistry;

        _options =
            options;
    }

    public Task<TransferFileEnforcementResult> ApplyCandidateBlockAsync(
        Guid sourceSecurityRuleId,
        SecurityDecisionRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            candidate);

        if (candidate.Confidence !=
            TransferCorrelationConfidence.High)
        {
            return Task.FromResult(
                new TransferFileEnforcementResult(
                    false,
                    true,
                    "Automatic temporary enforcement requires High confidence.",
                    null));
        }

        var processPath =
            candidate.Connection.Process?.ExecutablePath ??
            candidate.Connection.ApplicationPath;

        return ApplyAsync(
            sourceSecurityRuleId,
            context.ProcessPath,
            context.RemoteAddress,
            context.RemotePort,
            protocol,
            cancellationToken);
    }

    public Task<TransferFileEnforcementResult> ApplyDecisionBlockAsync(
        SecurityDecisionRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            request);

        var context =
            request.RuleContext ??
            throw new InvalidOperationException(
                "TransferGuard file decision context is missing.");

        if (!Enum.TryParse<TransferProtocol>(
                context.Protocol,
                true,
                out var protocol))
        {
            throw new InvalidOperationException(
                "TransferGuard protocol is missing or invalid.");
        }

        return ApplyAsync(
            context.ProcessPath,
            context.RemoteAddress,
            context.RemotePort,
            protocol,
            cancellationToken);
    }

    private async Task<TransferFileEnforcementResult> ApplyAsync(
        Guid sourceSecurityRuleId,
        string? processPath,
        string? remoteAddress,
        int? remotePort,
        TransferProtocol protocol,
        CancellationToken cancellationToken)
    {
        var settings =
            _runtimeState.CurrentSettings;

        if (!settings.Enabled)
        {
            return new TransferFileEnforcementResult(
                false,
                true,
                "TransferGuard is disabled.",
                null);
        }

        if (sourceSecurityRuleId ==
            Guid.Empty)
        {
            throw new TransferFileEnforcementException(
                "Source FileTransfer rule ID is missing.");
        }

        if (settings.Mode ==
            TransferGuardMode.Monitor)
        {
            return new TransferFileEnforcementResult(
                false,
                true,
                "TransferGuard is in Monitor mode.",
                null);
        }

        processPath =
            _pathNormalizer.Normalize(
                processPath);

        if (string.IsNullOrWhiteSpace(
                processPath) ||
            !Path.IsPathFullyQualified(
                processPath))
        {
            return await HandleFailureAsync(
                "Temporary file enforcement requires a fully qualified process path.",
                settings);
        }

        if (string.IsNullOrWhiteSpace(
                remoteAddress) ||
            !IPAddress.TryParse(
                remoteAddress,
                out _))
        {
            return await HandleFailureAsync(
                "Temporary file enforcement requires a valid remote address.",
                settings);
        }

        if (remotePort is null ||
            remotePort is < 1 or > 65535)
        {
            return await HandleFailureAsync(
                "Temporary file enforcement requires a valid remote port.",
                settings);
        }

        var id =
            TransferTemporaryBlockIdentity.Create(
                sourceSecurityRuleId,
                processPath,
                remoteAddress,
                remotePort.Value,
                protocol);

        var expires =
            DateTimeOffset.UtcNow +
            _options.FileBlockEnforcementLifetime;

        TransferTemporaryEnforcementResult result;

        try
        {
            result =
                await _temporaryEnforcement.AddOrRefreshAsync(
                    new TransferTemporaryEnforcementRule(
                        id,
                        sourceSecurityRuleId,
                        processPath,
                        remoteAddress,
                        remotePort.Value,
                        protocol,
                        expires),
                    cancellationToken);
        }
        catch (Exception exception)
        {
            if (settings.FailurePolicy ==
                TransferEnforcementFailurePolicy.FailClosed)
            {
                throw new TransferFileEnforcementException(
                    exception.Message,
                    exception);
            }

            _moduleRegistry.Set(
                SecurityModuleKind.TransferGuard,
                ModuleOperationalState.Degraded,
                "Temporary file-transfer enforcement failed");

            return new TransferFileEnforcementResult(
                false,
                false,
                exception.Message,
                null);
        }

        if (!result.Applied)
        {
            return await HandleFailureAsync(
                result.Message,
                settings);
        }

        return new TransferFileEnforcementResult(
            true,
            false,
            result.Message,
            result.ExpiresAtUtc);
    }

    private Task<TransferFileEnforcementResult> HandleFailureAsync(
        string message,
        TransferGuardSettings settings)
    {
        if (settings.FailurePolicy ==
            TransferEnforcementFailurePolicy.FailClosed)
        {
            throw new TransferFileEnforcementException(
                message);
        }

        _moduleRegistry.Set(
            SecurityModuleKind.TransferGuard,
            ModuleOperationalState.Degraded,
            "Temporary file-transfer enforcement failed");

        return Task.FromResult(
            new TransferFileEnforcementResult(
                false,
                false,
                message,
                null));
    }
}