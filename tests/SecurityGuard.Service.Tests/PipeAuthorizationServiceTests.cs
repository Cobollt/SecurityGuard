using SecurityGuard.Core.Ipc;
using SecurityGuard.Service.Ipc;

namespace SecurityGuard.Service.Tests;

public sealed class PipeAuthorizationServiceTests
{
    private readonly PipeAuthorizationService _service =
        new();

    [Fact]
    public void Standard_user_can_read_snapshot()
    {
        var context =
            new PipeClientContext(
                @"DESKTOP\User",
                false);

        Assert.True(
            _service.IsAuthorized(
                PipeMessageType.GetSnapshot,
                context));
    }

    [Fact]
    public void Standard_user_cannot_submit_decision()
    {
        var context =
            new PipeClientContext(
                @"DESKTOP\User",
                false);

        Assert.False(
            _service.IsAuthorized(
                PipeMessageType.SubmitDecision,
                context));
    }

    [Fact]
    public void Administrator_can_submit_decision()
    {
        var context =
            new PipeClientContext(
                @"DESKTOP\Admin",
                true);

        Assert.True(
            _service.IsAuthorized(
                PipeMessageType.SubmitDecision,
                context));
    }

    [Fact]
    public void Standard_user_cannot_delete_rule()
    {
        var context =
            new PipeClientContext(
                @"DESKTOP\User",
                false);

        Assert.False(
            _service.IsAuthorized(
                PipeMessageType.DeleteRule,
                context));
    }
}