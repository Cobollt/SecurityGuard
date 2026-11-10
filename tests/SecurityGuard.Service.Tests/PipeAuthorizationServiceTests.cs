using SecurityGuard.Core.Ipc;
using SecurityGuard.Service.Ipc;

namespace SecurityGuard.Service.Tests;

public sealed class PipeAuthorizationServiceTests
{
    private readonly PipeAuthorizationService _service =
        new();

    [Theory]
    [InlineData(PipeMessageType.SubmitDecision)]
    [InlineData(PipeMessageType.DeleteRule)]
    [InlineData(PipeMessageType.UpdateAlgorithmGuardSettings)]
    [InlineData(PipeMessageType.UpdateTransferGuardSettings)]
    [InlineData(PipeMessageType.CreateTransferGuardRule)]
    [InlineData(PipeMessageType.UpdateArchiveGuardSettings)]
    [InlineData(PipeMessageType.ExportSecurityLists)]
    [InlineData(PipeMessageType.ImportSecurityLists)]
    [InlineData(PipeMessageType.RestoreArchiveFromQuarantineWithException)]
    public void Mutating_commands_require_administrator(PipeMessageType command)
    {
        Assert.False(_service.IsAuthorized(command, new PipeClientContext("User", false)));
        Assert.True(_service.IsAuthorized(command, new PipeClientContext("Admin", true)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Unknown_and_unsupported_commands_are_denied(bool administrator)
    {
        var context = new PipeClientContext("User", administrator);
        Assert.False(_service.IsAuthorized((PipeMessageType)999, context));
        Assert.False(_service.IsAuthorized(PipeMessageType.ApplyArchiveDecision, context));
    }

    [Theory]
    [InlineData(PipeMessageType.Ping)]
    [InlineData(PipeMessageType.GetSnapshot)]
    [InlineData(PipeMessageType.GetRules)]
    [InlineData(PipeMessageType.GetAlgorithmGuardSettings)]
    [InlineData(PipeMessageType.GetTransferGuardSettings)]
    [InlineData(PipeMessageType.GetScanResults)]
    [InlineData(PipeMessageType.GetScanResult)]
    [InlineData(PipeMessageType.ScanFile)]
    [InlineData(PipeMessageType.GetArchiveGuardSettings)]
    [InlineData(PipeMessageType.ValidateSecurityLists)]
    [InlineData(PipeMessageType.GetSecurityListsFolder)]
    [InlineData(PipeMessageType.GetArchiveGuardQuarantineItems)]
    public void Read_and_scan_commands_remain_available_to_standard_users(PipeMessageType command)
    {
        Assert.True(_service.IsAuthorized(command, new PipeClientContext("User", false)));
    }

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