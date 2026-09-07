using SecurityGuard.AlgorithmGuard.Enums;
using SecurityGuard.AlgorithmGuard.Services;
using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.AlgorithmGuard.Parsing;

namespace SecurityGuard.AlgorithmGuard.Tests;

public sealed class InterpreterCatalogTests
{
    [Theory]
    [InlineData("powershell.exe", InterpreterKind.PowerShell)]
    [InlineData("pwsh.exe", InterpreterKind.PowerShell)]
    [InlineData("cmd.exe", InterpreterKind.CommandShell)]
    [InlineData("wscript.exe", InterpreterKind.WindowsScriptHost)]
    [InlineData("cscript.exe", InterpreterKind.WindowsScriptHost)]
    [InlineData("python.exe", InterpreterKind.Python)]
    [InlineData("python3.exe", InterpreterKind.Python)]
    [InlineData("pythonw.exe", InterpreterKind.Python)]
    [InlineData("py.exe", InterpreterKind.Python)]
    [InlineData("pyw.exe", InterpreterKind.Python)]
    public void Known_interpreter_is_detected(
        string processName,
        InterpreterKind expected)
    {
        var catalog =
            new InterpreterCatalog();

        var result =
            catalog.TryGetInterpreter(
                processName,
                out var interpreter);

        Assert.True(result);

        Assert.Equal(
            expected,
            interpreter);
    }

    [Fact]
    public void Normal_application_is_not_interpreter()
    {
        var catalog =
            new InterpreterCatalog();

        var result =
            catalog.TryGetInterpreter(
                "notepad.exe",
                out _);

        Assert.False(result);
    }

    [Theory]
    [InlineData("test.wsf")]
    [InlineData("test.vbs")]
    [InlineData("test.vbe")]
    [InlineData("test.js")]
    [InlineData("test.jse")]
    public void Windows_script_host_file_is_detected(
        string fileName)
    {
        var result =
            Analyze(
                "cscript.exe",
                $"cscript.exe C:\\Temp\\{fileName}");

        Assert.NotNull(
            result);

        Assert.Equal(
            AlgorithmInvocationType.ScriptFile,
            result.InvocationType);
    }

    private static AlgorithmExecutionAttempt? Analyze(
        string processName,
        string commandLine)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new AlgorithmExecutionAttempt(
                Guid.NewGuid(),
                1,
                null,
                processName,
                null,
                commandLine,
                InterpreterKind.WindowsScriptHost,
                AlgorithmInvocationType.ScriptFile,
                commandLine
                    .Split(
                        ' ',
                        StringSplitOptions.RemoveEmptyEntries)
                    .Last(),
                null,
                DateTimeOffset.UtcNow);
        }

        var analyzer =
            new AlgorithmExecutionAnalyzer(
                new InterpreterCatalog(),
                new WindowsCommandLineParser());

        return analyzer.Analyze(
            new ProcessStartSignal(
                1,
                null,
                processName,
                DateTimeOffset.UtcNow),
            new ProcessMetadata(
                1,
                null,
                processName,
                null,
                commandLine));
    }
}