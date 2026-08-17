using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Ipc;
using SecurityGuard.Core.Models;

namespace SecurityGuard.Service.Ipc;

public sealed class PipeRequestHandler
{
    private readonly ISecuritySnapshotService _snapshotService;
    private readonly ISecurityDecisionService _decisionService;

    public PipeRequestHandler(
        ISecuritySnapshotService snapshotService,
        ISecurityDecisionService decisionService)
    {
        _snapshotService = snapshotService;
        _decisionService = decisionService;
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
            PipeJsonSerializer.Serialize(snapshot));
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
}