using SecurityGuard.AlgorithmGuard.Enums;
using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.AlgorithmGuard.Services;

namespace SecurityGuard.AlgorithmGuard.Tests;

public sealed class AlgorithmExecutionIdentityTests
{
    [Fact]
    public void Same_context_has_same_identity()
    {
        var first =
            Create(
                @"DESKTOP\User",
                "explorer.exe");

        var second =
            Create(
                @"DESKTOP\User",
                "explorer.exe");

        Assert.Equal(
            AlgorithmExecutionIdentity.Create(
                first),
            AlgorithmExecutionIdentity.Create(
                second));
    }

    [Fact]
    public void Different_user_has_different_identity()
    {
        var first =
            Create(
                @"DESKTOP\UserA",
                "explorer.exe");

        var second =
            Create(
                @"DESKTOP\UserB",
                "explorer.exe");

        Assert.NotEqual(
            AlgorithmExecutionIdentity.Create(
                first),
            AlgorithmExecutionIdentity.Create(
                second));
    }

    [Fact]
    public void Different_parent_has_different_identity()
    {
        var first =
            Create(
                @"DESKTOP\User",
                "explorer.exe");

        var second =
            Create(
                @"DESKTOP\User",
                "backup.exe");

        Assert.NotEqual(
            AlgorithmExecutionIdentity.Create(
                first),
            AlgorithmExecutionIdentity.Create(
                second));
    }

    private static AlgorithmExecutionAttempt Create(
        string user,
        string parent)
    {
        return new AlgorithmExecutionAttempt(
            Guid.NewGuid(),
            100,
            50,
            "powershell.exe",
            @"C:\Windows\powershell.exe",
            @"powershell.exe -File C:\Temp\Test.ps1",
            InterpreterKind.PowerShell,
            AlgorithmInvocationType.ScriptFile,
            @"C:\Temp\Test.ps1",
            "ABC123",
            DateTimeOffset.UtcNow,
            user,
            parent,
            $@"C:\Test\{parent}",
            "Microsoft",
            "Valid",
            null,
            "NotSigned");
    }
}