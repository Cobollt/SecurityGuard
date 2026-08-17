using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Ipc;
using SecurityGuard.Core.Models;
using SecurityGuard.Service.Ipc;

namespace SecurityGuard.Service.Tests;

public sealed class PipeRequestHandlerTests
{
    [Fact]
    public async Task Ping_returns_pong()
    {
        var handler =
            new PipeRequestHandler(
                new FakeSnapshotService(),
                new FakeDecisionService());

        var request =
            PipeRequest.Create(
                PipeMessageType.Ping);

        var response =
            await handler.HandleAsync(
                request);

        Assert.True(
            response.Success);

        Assert.Equal(
            "PONG",
            response.Payload);

        Assert.Equal(
            request.Id,
            response.RequestId);
    }

    private sealed class FakeSnapshotService
        : ISecuritySnapshotService
    {
        public Task<SecuritySnapshot> GetAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                new SecuritySnapshot(
                    [],
                    [],
                    [],
                    0,
                    DateTimeOffset.UtcNow));
        }
    }

    private sealed class FakeDecisionService
        : ISecurityDecisionService
    {
        public Task ApplyAsync(
            SecurityDecision decision,
            CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }
    }
}