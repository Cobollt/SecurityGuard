using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.AlgorithmGuard.Services;

namespace SecurityGuard.AlgorithmGuard.Tests;

public sealed class AlgorithmExecutionChainIdTests
{
    [Fact]
    public void Nested_interpreters_share_correlation_id()
    {
        var catalog =
            new InterpreterCatalog();

        var cmdCreated =
            DateTimeOffset.UtcNow;

        var cmd =
            new ProcessMetadata(
                100,
                10,
                "cmd.exe",
                @"C:\Windows\System32\cmd.exe",
                "cmd.exe /c powershell.exe",
                CreatedAtUtc:
                    cmdCreated);

        var cmdAncestors =
            new[]
            {
                new ProcessAncestryEntry(
                    10,
                    1,
                    "explorer.exe",
                    @"C:\Windows\explorer.exe",
                    cmdCreated -
                    TimeSpan.FromMinutes(10))
            };

        var powershell =
            new ProcessMetadata(
                200,
                100,
                "powershell.exe",
                @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "powershell.exe -File test.ps1",
                CreatedAtUtc:
                    cmdCreated +
                    TimeSpan.FromSeconds(1));

        var powershellAncestors =
            new[]
            {
                new ProcessAncestryEntry(
                    100,
                    10,
                    "cmd.exe",
                    @"C:\Windows\System32\cmd.exe",
                    cmdCreated),

                new ProcessAncestryEntry(
                    10,
                    1,
                    "explorer.exe",
                    @"C:\Windows\explorer.exe",
                    cmdCreated -
                    TimeSpan.FromMinutes(10))
            };

        var first =
            AlgorithmExecutionChainId.Create(
                cmd,
                cmdAncestors,
                catalog);

        var second =
            AlgorithmExecutionChainId.Create(
                powershell,
                powershellAncestors,
                catalog);

        Assert.Equal(
            first,
            second);
    }
}