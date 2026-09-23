using System.IO.Pipes;
using SecurityGuard.Core.Ipc;
using SecurityGuard.Core.Models;
using SecurityGuard.AlgorithmGuard.Models;
using System.Security.Principal;
using SecurityGuard.TransferGuard.Models;
using System.IO;
using SecurityGuard.Core.Ipc.ArchiveGuard;
using SecurityGuard.Core.Ipc.SecurityLists;
using SecurityGuard.Core.Lists;

namespace SecurityGuard.UI.Services;

public sealed class SecurityGuardClient
    : ISecurityGuardClient
{
    public async Task<bool> PingAsync(
        CancellationToken cancellationToken = default)
    {
        var request =
            PipeRequest.Create(
                PipeMessageType.Ping);

        var response =
            await SendAsync(
                request,
                cancellationToken);

        return response.Success &&
               response.Payload == "PONG";
    }

    public async Task<SecuritySnapshot> GetSnapshotAsync(
        CancellationToken cancellationToken = default)
    {
        var request =
            PipeRequest.Create(
                PipeMessageType.GetSnapshot);

        var response =
            await SendAsync(
                request,
                cancellationToken);

        EnsureSuccess(response);

        if (string.IsNullOrWhiteSpace(
                response.Payload))
        {
            throw new InvalidDataException(
                "Snapshot response is empty.");
        }

        return PipeJsonSerializer.Deserialize<SecuritySnapshot>(
            response.Payload);
    }

    public async Task<IReadOnlyList<SecurityRule>> GetRulesAsync(
        CancellationToken cancellationToken = default)
    {
        var request =
            PipeRequest.Create(
                PipeMessageType.GetRules);

        var response =
            await SendAsync(
                request,
                cancellationToken);

        EnsureSuccess(response);

        if (string.IsNullOrWhiteSpace(
                response.Payload))
        {
            return [];
        }

        return PipeJsonSerializer.Deserialize<List<SecurityRule>>(
            response.Payload);
    }

    public async Task SubmitDecisionAsync(
        SecurityDecision decision,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            decision);

        var request =
            PipeRequest.Create(
                PipeMessageType.SubmitDecision,
                PipeJsonSerializer.Serialize(
                    decision));

        var response =
            await SendAsync(
                request,
                cancellationToken);

        EnsureSuccess(response);
    }

    public async Task DeleteRuleAsync(
        Guid ruleId,
        CancellationToken cancellationToken = default)
    {
        var payload =
            new DeleteSecurityRuleRequest(
                ruleId);

        var request =
            PipeRequest.Create(
                PipeMessageType.DeleteRule,
                PipeJsonSerializer.Serialize(
                    payload));

        var response =
            await SendAsync(
                request,
                cancellationToken);

        EnsureSuccess(response);
    }

    private static async Task<PipeResponse> SendAsync(
        PipeRequest request,
        CancellationToken cancellationToken)
    {
        await using var pipe =
            new NamedPipeClientStream(
                ".",
                PipeProtocol.PipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous,
                TokenImpersonationLevel.Impersonation);

        await pipe.ConnectAsync(
            3000,
            cancellationToken);

        await PipeMessageIO.WriteAsync(
            pipe,
            request,
            cancellationToken);

        var response =
            await PipeMessageIO.ReadAsync<PipeResponse>(
                pipe,
                cancellationToken);

        if (response.RequestId !=
            request.Id)
        {
            throw new InvalidDataException(
                "IPC response does not match request.");
        }

        return response;
    }

    private static void EnsureSuccess(
        PipeResponse response)
    {
        if (!response.Success)
        {
            throw new InvalidOperationException(
                response.Error ??
                "SecurityGuard service request failed.");
        }
    }

    public async Task<AlgorithmGuardSettings> GetAlgorithmGuardSettingsAsync(
    CancellationToken cancellationToken = default)
{
    var request =
        PipeRequest.Create(
            PipeMessageType.GetAlgorithmGuardSettings);

    var response =
        await SendAsync(
            request,
            cancellationToken);

    EnsureSuccess(
        response);

    if (string.IsNullOrWhiteSpace(
            response.Payload))
    {
        throw new InvalidDataException(
            "AlgorithmGuard settings response is empty.");
    }

    return PipeJsonSerializer.Deserialize<AlgorithmGuardSettings>(
        response.Payload);
}

    public async Task UpdateAlgorithmGuardSettingsAsync(
        AlgorithmGuardSettings settings,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            settings);

        var request =
            PipeRequest.Create(
                PipeMessageType.UpdateAlgorithmGuardSettings,
                PipeJsonSerializer.Serialize(
                    settings));

        var response =
            await SendAsync(
                request,
                cancellationToken);

        EnsureSuccess(
            response);
    }

    public async Task<TransferGuardSettings> GetTransferGuardSettingsAsync(
        CancellationToken cancellationToken = default)
    {
        var request =
            PipeRequest.Create(
                PipeMessageType.GetTransferGuardSettings);

        var response =
            await SendAsync(
                request,
                cancellationToken);

        EnsureSuccess(
            response);

        if (string.IsNullOrWhiteSpace(
                response.Payload))
        {
            throw new InvalidDataException(
                "TransferGuard settings response is empty.");
        }

        return PipeJsonSerializer.Deserialize<TransferGuardSettings>(
            response.Payload);
    }

    public async Task UpdateTransferGuardSettingsAsync(
        TransferGuardSettings settings,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            settings);

        var request =
            PipeRequest.Create(
                PipeMessageType.UpdateTransferGuardSettings,
                PipeJsonSerializer.Serialize(
                    settings));

        var response =
            await SendAsync(
                request,
                cancellationToken);

        EnsureSuccess(
            response);
    }

    public async Task<SecurityRule> CreateTransferGuardRuleAsync(
        TransferManualRuleRequest model,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            model);

        var request =
            PipeRequest.Create(
                PipeMessageType.CreateTransferGuardRule,
                PipeJsonSerializer.Serialize(
                    model));

        var response =
            await SendAsync(
                request,
                cancellationToken);

        EnsureSuccess(
            response);

        if (string.IsNullOrWhiteSpace(
                response.Payload))
        {
            throw new InvalidDataException(
                "Created TransferGuard rule response is empty.");
        }

        return PipeJsonSerializer.Deserialize<SecurityRule>(
            response.Payload);
    }

    public async Task<ArchiveGuardScanIpcDto> ScanArchiveGuardAsync(
        string filePath,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            filePath);

        var payload =
            new ArchiveGuardScanIpcRequest(
                filePath);

        var request =
            PipeRequest.Create(
                PipeMessageType.ScanFile,
                PipeJsonSerializer.Serialize(
                    payload));

        var response =
            await SendAsync(
                request,
                cancellationToken);

        EnsureSuccess(
            response);

        if (string.IsNullOrWhiteSpace(
                response.Payload))
        {
            throw new InvalidDataException(
                "ArchiveGuard scan response is empty.");
        }

        return PipeJsonSerializer.Deserialize<ArchiveGuardScanIpcDto>(
            response.Payload);
    }

    public async Task<IReadOnlyList<ArchiveGuardRecentScanIpcDto>> GetArchiveGuardRecentScansAsync(
        int limit = 50,
        CancellationToken cancellationToken = default)
    {
        var payload =
            new ArchiveGuardRecentScansIpcRequest(
                limit);

        var request =
            PipeRequest.Create(
                PipeMessageType.GetScanResults,
                PipeJsonSerializer.Serialize(
                    payload));

        var response =
            await SendAsync(
                request,
                cancellationToken);

        EnsureSuccess(
            response);

        if (string.IsNullOrWhiteSpace(
                response.Payload))
        {
            return [];
        }

        return PipeJsonSerializer.Deserialize<
            List<ArchiveGuardRecentScanIpcDto>>(
                response.Payload);
    }

    public async Task<IReadOnlyList<ArchiveGuardQuarantineItemIpcDto>> GetArchiveGuardQuarantineItemsAsync(
        int limit = 200,
        CancellationToken cancellationToken = default)
    {
        var payload =
            new ArchiveGuardQuarantineItemsIpcRequest(
                limit);

        var request =
            PipeRequest.Create(
                PipeMessageType.GetArchiveGuardQuarantineItems,
                PipeJsonSerializer.Serialize(
                    payload));

        var response =
            await SendAsync(
                request,
                cancellationToken);

        EnsureSuccess(
            response);

        if (string.IsNullOrWhiteSpace(
                response.Payload))
        {
            return [];
        }

        return PipeJsonSerializer.Deserialize<
            List<ArchiveGuardQuarantineItemIpcDto>>(
                response.Payload);
    }

    public async Task<ArchiveGuardQuarantineRestoreIpcDto> RestoreArchiveFromQuarantineWithExceptionAsync(
        Guid quarantineId,
        CancellationToken cancellationToken = default)
    {
        if (quarantineId == Guid.Empty)
        {
            throw new ArgumentException(
                "Quarantine ID is required.",
                nameof(quarantineId));
        }

        var payload =
            new ArchiveGuardQuarantineRestoreIpcRequest(
                quarantineId);

        var request =
            PipeRequest.Create(
                PipeMessageType.RestoreArchiveFromQuarantineWithException,
                PipeJsonSerializer.Serialize(
                    payload));

        var response =
            await SendAsync(
                request,
                cancellationToken);

        EnsureSuccess(
            response);

        if (string.IsNullOrWhiteSpace(
                response.Payload))
        {
            throw new InvalidDataException(
                "ArchiveGuard quarantine restore response is empty.");
        }

        return PipeJsonSerializer.Deserialize<
            ArchiveGuardQuarantineRestoreIpcDto>(
                response.Payload);
    }

    public async Task<ArchiveGuardAutoScanSettingsIpcDto> GetArchiveGuardAutoScanSettingsAsync(
        CancellationToken cancellationToken = default)
    {
        var request =
            PipeRequest.Create(
                PipeMessageType.GetArchiveGuardSettings);

        var response =
            await SendAsync(
                request,
                cancellationToken);

        EnsureSuccess(
            response);

        if (string.IsNullOrWhiteSpace(
                response.Payload))
        {
            throw new InvalidDataException(
                "ArchiveGuard settings response is empty.");
        }

        return PipeJsonSerializer.Deserialize<
            ArchiveGuardAutoScanSettingsIpcDto>(
                response.Payload);
    }

    public async Task<ArchiveGuardAutoScanSettingsIpcDto> UpdateArchiveGuardAutoScanSettingsAsync(
        ArchiveGuardUpdateAutoScanSettingsIpcRequest settings,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            settings);

        var request =
            PipeRequest.Create(
                PipeMessageType.UpdateArchiveGuardSettings,
                PipeJsonSerializer.Serialize(
                    settings));

        var response =
            await SendAsync(
                request,
                cancellationToken);

        EnsureSuccess(
            response);

        if (string.IsNullOrWhiteSpace(
                response.Payload))
        {
            throw new InvalidDataException(
                "ArchiveGuard settings response is empty.");
        }

        return PipeJsonSerializer.Deserialize<
            ArchiveGuardAutoScanSettingsIpcDto>(
                response.Payload);
    }

    public async Task<SecurityListExportIpcDto> ExportSecurityListsAsync(
        CancellationToken cancellationToken = default)
    {
        var request =
            PipeRequest.Create(
                PipeMessageType.ExportSecurityLists);

        var response =
            await SendAsync(
                request,
                cancellationToken);

        EnsureSuccess(
            response);

        if (string.IsNullOrWhiteSpace(
                response.Payload))
        {
            throw new InvalidDataException(
                "Security list export response is empty.");
        }

        return PipeJsonSerializer.Deserialize<
            SecurityListExportIpcDto>(
                response.Payload);
    }

    public async Task<SecurityListValidationIpcDto> ValidateSecurityListsAsync(
        string packagePath,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            packagePath);

        var payload =
            new SecurityListValidateIpcRequest(
                packagePath);

        var request =
            PipeRequest.Create(
                PipeMessageType.ValidateSecurityLists,
                PipeJsonSerializer.Serialize(
                    payload));

        var response =
            await SendAsync(
                request,
                cancellationToken);

        EnsureSuccess(
            response);

        if (string.IsNullOrWhiteSpace(
                response.Payload))
        {
            throw new InvalidDataException(
                "Security list validation response is empty.");
        }

        return PipeJsonSerializer.Deserialize<
            SecurityListValidationIpcDto>(
                response.Payload);
    }

    public async Task<SecurityListImportIpcDto> ImportSecurityListsAsync(
        string packagePath,
        SecurityListImportMode mode = SecurityListImportMode.Merge,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            packagePath);

        var payload =
            new SecurityListImportIpcRequest(
                packagePath,
                mode);

        var request =
            PipeRequest.Create(
                PipeMessageType.ImportSecurityLists,
                PipeJsonSerializer.Serialize(
                    payload));

        var response =
            await SendAsync(
                request,
                cancellationToken);

        EnsureSuccess(
            response);

        if (string.IsNullOrWhiteSpace(
                response.Payload))
        {
            throw new InvalidDataException(
                "Security list import response is empty.");
        }

        return PipeJsonSerializer.Deserialize<
            SecurityListImportIpcDto>(
                response.Payload);
    }

    public async Task<SecurityListFoldersIpcDto> GetSecurityListsFoldersAsync(
        CancellationToken cancellationToken = default)
    {
        var request =
            PipeRequest.Create(
                PipeMessageType.GetSecurityListsFolder);

        var response =
            await SendAsync(
                request,
                cancellationToken);

        EnsureSuccess(
            response);

        if (string.IsNullOrWhiteSpace(
                response.Payload))
        {
            throw new InvalidDataException(
                "Security lists folder response is empty.");
        }

        return PipeJsonSerializer.Deserialize<
            SecurityListFoldersIpcDto>(
                response.Payload);
    }
}