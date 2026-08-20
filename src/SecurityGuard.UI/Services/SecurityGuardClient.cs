using System.IO.Pipes;
using SecurityGuard.Core.Ipc;
using SecurityGuard.Core.Models;

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
                PipeOptions.Asynchronous);

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
}