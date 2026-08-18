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
}