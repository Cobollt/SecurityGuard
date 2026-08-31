using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Ipc;
using SecurityGuard.Core.Models;
using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.Service.Ipc;

public sealed class PipeRequestHandler
{
    private readonly ISecuritySnapshotService _snapshotService;
    private readonly ISecurityDecisionService _decisionService;
    private readonly IRuleManagementService _ruleManagementService;
    private readonly IAlgorithmGuardSettingsCoordinator _algorithmGuardSettings;
    private readonly ITransferGuardSettingsCoordinator _transferGuardSettings;
    private readonly ITransferManualRuleService _transferManualRuleService;

    public PipeRequestHandler(
        ISecuritySnapshotService snapshotService,
        ISecurityDecisionService decisionService,
        IRuleManagementService ruleManagementService,
        IAlgorithmGuardSettingsCoordinator algorithmGuardSettings,
        ITransferGuardSettingsCoordinator transferGuardSettings,
        ITransferManualRuleService transferManualRuleService)
    {
        _snapshotService =
            snapshotService;

        _decisionService =
            decisionService;

        _ruleManagementService =
            ruleManagementService;

        _algorithmGuardSettings =
            algorithmGuardSettings;

        _transferGuardSettings =
            transferGuardSettings;

        _transferManualRuleService =
            transferManualRuleService;
    }   

    public async Task<PipeResponse> HandleAsync(
        PipeRequest request,
        CancellationToken cancellationToken = default)
    {
        try
        {
            return request.Type switch
            {
                PipeMessageType.Ping =>
                    PipeResponse.Ok(
                        request.Id,
                        "PONG"),

                PipeMessageType.GetSnapshot =>
                    await GetSnapshotAsync(
                        request,
                        cancellationToken),

                PipeMessageType.SubmitDecision =>
                    await SubmitDecisionAsync(
                        request,
                        cancellationToken),

                PipeMessageType.GetRules =>
                    await GetRulesAsync(
                        request,
                        cancellationToken),

                PipeMessageType.DeleteRule =>
                    await DeleteRuleAsync(
                        request,
                        cancellationToken),

                PipeMessageType.GetAlgorithmGuardSettings =>
                    await GetAlgorithmGuardSettingsAsync(
                        request,
                        cancellationToken),

                PipeMessageType.UpdateAlgorithmGuardSettings =>
                    await UpdateAlgorithmGuardSettingsAsync(
                        request,
                        cancellationToken),

                PipeMessageType.GetTransferGuardSettings =>
                    await GetTransferGuardSettingsAsync(
                        request,
                        cancellationToken),

                PipeMessageType.UpdateTransferGuardSettings =>
                    await UpdateTransferGuardSettingsAsync(
                        request,
                        cancellationToken),
                    
                PipeMessageType.CreateTransferGuardRule =>
                    await CreateTransferGuardRuleAsync(
                        request,
                        cancellationToken),

                _ =>
                    PipeResponse.Fail(
                        request.Id,
                        $"Unsupported IPC command: {request.Type}")
            };
        }
        catch (Exception exception)
        {
            return PipeResponse.Fail(
                request.Id,
                exception.Message);
        }
    }

    private async Task<PipeResponse> GetSnapshotAsync(
        PipeRequest request,
        CancellationToken cancellationToken)
    {
        var snapshot =
            await _snapshotService.GetAsync(
                cancellationToken);

        return PipeResponse.Ok(
            request.Id,
            PipeJsonSerializer.Serialize(
                snapshot));
    }

    private async Task<PipeResponse> SubmitDecisionAsync(
        PipeRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(
                request.Payload))
        {
            return PipeResponse.Fail(
                request.Id,
                "Decision payload is required.");
        }

        var decision =
            PipeJsonSerializer.Deserialize<SecurityDecision>(
                request.Payload);

        await _decisionService.ApplyAsync(
            decision,
            cancellationToken);

        return PipeResponse.Ok(
            request.Id);
    }

    private async Task<PipeResponse> GetRulesAsync(
        PipeRequest request,
        CancellationToken cancellationToken)
    {
        var rules =
            await _ruleManagementService.GetAllAsync(
                cancellationToken);

        return PipeResponse.Ok(
            request.Id,
            PipeJsonSerializer.Serialize(
                rules));
    }

    private async Task<PipeResponse> DeleteRuleAsync(
        PipeRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(
                request.Payload))
        {
            return PipeResponse.Fail(
                request.Id,
                "Delete rule payload is required.");
        }

        var deleteRequest =
            PipeJsonSerializer.Deserialize<DeleteSecurityRuleRequest>(
                request.Payload);

        await _ruleManagementService.DeleteAsync(
            deleteRequest.RuleId,
            cancellationToken);

        return PipeResponse.Ok(
            request.Id);
    }

        private async Task<PipeResponse> GetAlgorithmGuardSettingsAsync(
        PipeRequest request,
        CancellationToken cancellationToken)
    {
        var settings =
            await _algorithmGuardSettings.GetAsync(
                cancellationToken);

        return PipeResponse.Ok(
            request.Id,
            PipeJsonSerializer.Serialize(
                settings));
    }

    private async Task<PipeResponse> UpdateAlgorithmGuardSettingsAsync(
        PipeRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(
                request.Payload))
        {
            return PipeResponse.Fail(
                request.Id,
                "AlgorithmGuard settings payload is required.");
        }

        var settings =
            PipeJsonSerializer.Deserialize<AlgorithmGuardSettings>(
                request.Payload);

        await _algorithmGuardSettings.UpdateAsync(
            settings,
            cancellationToken);

        return PipeResponse.Ok(
            request.Id);
    }

    private async Task<PipeResponse> GetTransferGuardSettingsAsync(
        PipeRequest request,
        CancellationToken cancellationToken)
    {
        var settings =
            await _transferGuardSettings.GetAsync(
                cancellationToken);

        return PipeResponse.Ok(
            request.Id,
            PipeJsonSerializer.Serialize(
                settings));
    }

    private async Task<PipeResponse> UpdateTransferGuardSettingsAsync(
        PipeRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(
                request.Payload))
        {
            return PipeResponse.Fail(
                request.Id,
                "TransferGuard settings payload is required.");
        }

        var settings =
            PipeJsonSerializer.Deserialize<TransferGuardSettings>(
                request.Payload);

        await _transferGuardSettings.UpdateAsync(
            settings,
            cancellationToken);

        return PipeResponse.Ok(
            request.Id);
    }

    private async Task<PipeResponse> CreateTransferGuardRuleAsync(
        PipeRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(
                request.Payload))
        {
            return PipeResponse.Fail(
                request.Id,
                "TransferGuard rule payload is required.");
        }

        var model =
            PipeJsonSerializer.Deserialize<TransferManualRuleRequest>(
                request.Payload);

        var rule =
            await _transferManualRuleService.CreateAsync(
                model,
                cancellationToken);

        return PipeResponse.Ok(
            request.Id,
            PipeJsonSerializer.Serialize(
                rule));
    }
}