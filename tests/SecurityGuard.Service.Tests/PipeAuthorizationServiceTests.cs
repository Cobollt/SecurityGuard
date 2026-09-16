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

    [Fact]
    public void Standard_user_cannot_create_transfer_rule()
    {
        var context =
            new PipeClientContext(
                @"DESKTOP\User",
                false);

        Assert.False(
            _service.IsAuthorized(
                PipeMessageType.CreateTransferGuardRule,
                context));
    }

    [Fact]
    public void Administrator_can_create_transfer_rule()
    {
        var context =
            new PipeClientContext(
                @"DESKTOP\Admin",
                true);

        Assert.True(
            _service.IsAuthorized(
                PipeMessageType.CreateTransferGuardRule,
                context));
    }

    [Fact]
    public void Standard_user_cannot_update_archive_guard_settings()
    {
        var context =
            new PipeClientContext(
                @"DESKTOP\User",
                false);

        Assert.False(
            _service.IsAuthorized(
                PipeMessageType.UpdateArchiveGuardSettings,
                context));
    }

    [Fact]
    public void Administrator_can_update_archive_guard_settings()
    {
        var context =
            new PipeClientContext(
                @"DESKTOP\Admin",
                true);

        Assert.True(
            _service.IsAuthorized(
                PipeMessageType.UpdateArchiveGuardSettings,
                context));
    }

    [Fact]
    public void Standard_user_cannot_export_security_lists()
    {
        var context =
            new PipeClientContext(
                @"DESKTOP\User",
                false);

        Assert.False(
            _service.IsAuthorized(
                PipeMessageType.ExportSecurityLists,
                context));
    }

    [Fact]
    public void Administrator_can_export_security_lists()
    {
        var context =
            new PipeClientContext(
                @"DESKTOP\Admin",
                true);

        Assert.True(
            _service.IsAuthorized(
                PipeMessageType.ExportSecurityLists,
                context));
    }

    [Fact]
    public void Standard_user_cannot_import_security_lists()
    {
        var context =
            new PipeClientContext(
                @"DESKTOP\User",
                false);

        Assert.False(
            _service.IsAuthorized(
                PipeMessageType.ImportSecurityLists,
                context));
    }

    [Fact]
    public void Administrator_can_import_security_lists()
    {
        var context =
            new PipeClientContext(
                @"DESKTOP\Admin",
                true);

        Assert.True(
            _service.IsAuthorized(
                PipeMessageType.ImportSecurityLists,
                context));
    }
}