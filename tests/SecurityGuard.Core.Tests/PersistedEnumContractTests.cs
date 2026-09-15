using SecurityGuard.Core.Enums;

namespace SecurityGuard.Core.Tests;

public sealed class PersistedEnumContractTests
{
    [Fact]
    public void Security_module_values_are_stable()
    {
        Assert.Equal(
            0,
            (int)SecurityModuleKind.Core);

        Assert.Equal(
            1,
            (int)SecurityModuleKind.AlgorithmGuard);

        Assert.Equal(
            2,
            (int)SecurityModuleKind.TransferGuard);

        Assert.Equal(
            3,
            (int)SecurityModuleKind.ArchiveGuard);
    }

    [Fact]
    public void Security_event_values_are_stable()
    {
        Assert.Equal(
            0,
            (int)SecurityEventType.System);

        Assert.Equal(
            1,
            (int)SecurityEventType.AlgorithmExecution);

        Assert.Equal(
            2,
            (int)SecurityEventType.FileTransfer);

        Assert.Equal(
            3,
            (int)SecurityEventType.FileScan);

        Assert.Equal(
            4,
            (int)SecurityEventType.ArchiveScan);

        Assert.Equal(
            5,
            (int)SecurityEventType.Quarantine);

        Assert.Equal(
            6,
            (int)SecurityEventType.Rule);

        Assert.Equal(
            7,
            (int)SecurityEventType.Audit);

        Assert.Equal(
            8,
            (int)SecurityEventType.NetworkConnection);
    }

    [Fact]
    public void Rule_scope_values_are_stable()
    {
        Assert.Equal(
            0,
            (int)RuleScope.FileHash);

        Assert.Equal(
            1,
            (int)RuleScope.FilePath);

        Assert.Equal(
            2,
            (int)RuleScope.FileName);

        Assert.Equal(
            3,
            (int)RuleScope.FileExtension);

        Assert.Equal(
            4,
            (int)RuleScope.Publisher);

        Assert.Equal(
            5,
            (int)RuleScope.Process);

        Assert.Equal(
            6,
            (int)RuleScope.ParentProcess);

        Assert.Equal(
            7,
            (int)RuleScope.Interpreter);

        Assert.Equal(
            8,
            (int)RuleScope.RemoteAddress);

        Assert.Equal(
            9,
            (int)RuleScope.RemotePort);

        Assert.Equal(
            10,
            (int)RuleScope.Protocol);

        Assert.Equal(
            11,
            (int)RuleScope.DestinationProcess);

        Assert.Equal(
            12,
            (int)RuleScope.CommandLine);

        Assert.Equal(
            13,
            (int)RuleScope.UserName);

        Assert.Equal(
            14,
            (int)RuleScope.ProcessPublisher);

        Assert.Equal(
            15,
            (int)RuleScope.ParentProcessPath);

        Assert.Equal(
            16,
            (int)RuleScope.RootProcess);

        Assert.Equal(
            17,
            (int)RuleScope.RootProcessPath);

        Assert.Equal(
            18,
            (int)RuleScope.ExecutionChain);

        Assert.Equal(
            19,
            (int)RuleScope.ProcessPath);

        Assert.Equal(
            20,
            (int)RuleScope.FileCategory);

        Assert.Equal(
            21,
            (int)RuleScope.TransferActivityKind);
    }
}