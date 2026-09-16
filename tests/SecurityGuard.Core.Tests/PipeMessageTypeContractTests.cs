using SecurityGuard.Core.Ipc;

namespace SecurityGuard.Core.Tests;

public sealed class PipeMessageTypeContractTests
{
    [Fact]
    public void Archive_guard_message_ids_are_stable()
    {
        Assert.Equal(
            10,
            (int)PipeMessageType.GetScanResults);

        Assert.Equal(
            11,
            (int)PipeMessageType.GetScanResult);

        Assert.Equal(
            12,
            (int)PipeMessageType.ScanFile);

        Assert.Equal(
            13,
            (int)PipeMessageType.ApplyArchiveDecision);

        Assert.Equal(
            14,
            (int)PipeMessageType.GetArchiveGuardSettings);

        Assert.Equal(
            15,
            (int)PipeMessageType.UpdateArchiveGuardSettings);
    }

    [Fact]
    public void Security_list_transfer_message_ids_are_stable()
    {
        Assert.Equal(
            16,
            (int)PipeMessageType.ExportSecurityLists);

        Assert.Equal(
            17,
            (int)PipeMessageType.ValidateSecurityLists);

        Assert.Equal(
            18,
            (int)PipeMessageType.ImportSecurityLists);

        Assert.Equal(
            19,
            (int)PipeMessageType.GetSecurityListsFolder);
    }
}