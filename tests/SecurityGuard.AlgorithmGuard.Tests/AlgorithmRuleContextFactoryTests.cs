using SecurityGuard.AlgorithmGuard.Enums;
using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.AlgorithmGuard.Services;

namespace SecurityGuard.AlgorithmGuard.Tests;

public sealed class AlgorithmRuleContextFactoryTests
{
    [Fact]
    public void Script_information_is_mapped_to_rule_context()
    {
        var attempt =
            new AlgorithmExecutionAttempt(
                Guid.NewGuid(),
                100,
                50,
                "powershell.exe",
                @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                @"powershell.exe -File C:\Temp\test.ps1",
                InterpreterKind.PowerShell,
                AlgorithmInvocationType.ScriptFile,
                @"C:\Temp\test.ps1",
                "ABC123",
                DateTimeOffset.UtcNow);

        var factory =
            new AlgorithmRuleContextFactory();

        var context =
            factory.Create(
                attempt);

        Assert.Equal(
            "ABC123",
            context.FileHash);

        Assert.Equal(
            @"C:\Temp\test.ps1",
            context.FilePath);

        Assert.Equal(
            "test.ps1",
            context.FileName);

        Assert.Equal(
            ".ps1",
            context.FileExtension);

        Assert.Equal(
            "powershell.exe",
            context.Process);

        Assert.Equal(
            "PowerShell",
            context.Interpreter);
    }

    [Fact]
    public void Process_security_context_is_mapped()
    {
        var attempt =
            new AlgorithmExecutionAttempt(
                Guid.NewGuid(),
                100,
                50,
                "powershell.exe",
                @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "powershell.exe -Command Get-Date",
                InterpreterKind.PowerShell,
                AlgorithmInvocationType.InlineCommand,
                null,
                null,
                DateTimeOffset.UtcNow,
                @"DESKTOP\User",
                "explorer.exe",
                @"C:\Windows\explorer.exe",
                "Microsoft Corporation",
                "Valid",
                null,
                null);

        var factory =
            new AlgorithmRuleContextFactory();

        var context =
            factory.Create(
                attempt);

        Assert.Equal(
            @"DESKTOP\User",
            context.UserName);

        Assert.Equal(
            "explorer.exe",
            context.ParentProcess);

        Assert.Equal(
            @"C:\Windows\explorer.exe",
            context.ParentProcessPath);

        Assert.Equal(
            "Microsoft Corporation",
            context.ProcessPublisher);

        Assert.Equal(
            "Microsoft Corporation",
            context.Publisher);
    }

    [Fact]
    public void Execution_chain_is_mapped()
    {
        var attempt =
            new AlgorithmExecutionAttempt(
                Guid.NewGuid(),
                300,
                200,
                "powershell.exe",
                @"C:\Windows\powershell.exe",
                "powershell.exe -File test.ps1",
                InterpreterKind.PowerShell,
                AlgorithmInvocationType.ScriptFile,
                @"C:\Temp\test.ps1",
                "ABC",
                DateTimeOffset.UtcNow,
                ExecutionChain:
                [
                    new ProcessAncestryEntry(
                        200,
                        100,
                        "cmd.exe",
                        @"C:\Windows\System32\cmd.exe",
                        DateTimeOffset.UtcNow),

                    new ProcessAncestryEntry(
                        100,
                        50,
                        "explorer.exe",
                        @"C:\Windows\explorer.exe",
                        DateTimeOffset.UtcNow)
                ]);

        var context =
            new AlgorithmRuleContextFactory()
                .Create(
                    attempt);

        Assert.Equal(
            "explorer.exe",
            context.RootProcess);

        Assert.Equal(
            @"C:\Windows\explorer.exe",
            context.RootProcessPath);

        Assert.Equal(
            "explorer.exe > cmd.exe > powershell.exe",
            context.ExecutionChain);
    }
}