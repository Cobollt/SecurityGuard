using SecurityGuard.AlgorithmGuard.Enums;
using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.AlgorithmGuard.Parsing;
using SecurityGuard.AlgorithmGuard.Services;

namespace SecurityGuard.AlgorithmGuard.Tests;

public sealed class AlgorithmExecutionAnalyzerTests
{
    private readonly AlgorithmExecutionAnalyzer _analyzer =
        new(
            new InterpreterCatalog(),
            new WindowsCommandLineParser());

    [Fact]
    public void PowerShell_script_is_detected()
    {
        var result =
            Analyze(
                "powershell.exe",
                """
                powershell.exe -File "C:\Temp\test.ps1"
                """);

        Assert.NotNull(result);

        Assert.Equal(
            InterpreterKind.PowerShell,
            result.Interpreter);

        Assert.Equal(
            AlgorithmInvocationType.ScriptFile,
            result.InvocationType);

        Assert.Equal(
            @"C:\Temp\test.ps1",
            result.ScriptPath);
    }

    [Fact]
    public void PowerShell_encoded_command_is_detected()
    {
        var result =
            Analyze(
                "powershell.exe",
                "powershell.exe -EncodedCommand AAAA");

        Assert.NotNull(result);

        Assert.Equal(
            AlgorithmInvocationType.EncodedCommand,
            result.InvocationType);

        Assert.Null(
            result.ScriptPath);
    }

    [Fact]
    public void PowerShell_inline_command_is_detected()
    {
        var result =
            Analyze(
                "powershell.exe",
                """
                powershell.exe -Command "Get-Process"
                """);

        Assert.NotNull(result);

        Assert.Equal(
            AlgorithmInvocationType.InlineCommand,
            result.InvocationType);
    }

    [Fact]
    public void Cmd_batch_file_is_detected()
    {
        var result =
            Analyze(
                "cmd.exe",
                """
                cmd.exe /c "C:\Temp\start.bat"
                """);

        Assert.NotNull(result);

        Assert.Equal(
            InterpreterKind.CommandShell,
            result.Interpreter);

        Assert.Equal(
            AlgorithmInvocationType.ScriptFile,
            result.InvocationType);

        Assert.Equal(
            @"C:\Temp\start.bat",
            result.ScriptPath);
    }

    [Fact]
    public void Python_script_is_detected()
    {
        var result =
            Analyze(
                "python.exe",
                """
                python.exe "C:\Temp\script.py"
                """);

        Assert.NotNull(result);

        Assert.Equal(
            InterpreterKind.Python,
            result.Interpreter);

        Assert.Equal(
            AlgorithmInvocationType.ScriptFile,
            result.InvocationType);
    }

    [Fact]
    public void Python_inline_command_is_detected()
    {
        var result =
            Analyze(
                "python.exe",
                """
                python.exe -c "print('test')"
                """);

        Assert.NotNull(result);

        Assert.Equal(
            AlgorithmInvocationType.InlineCommand,
            result.InvocationType);
    }

    [Fact]
    public void Wscript_script_is_detected()
    {
        var result =
            Analyze(
                "wscript.exe",
                """
                wscript.exe "C:\Temp\test.vbs"
                """);

        Assert.NotNull(result);

        Assert.Equal(
            InterpreterKind.WindowsScriptHost,
            result.Interpreter);

        Assert.Equal(
            AlgorithmInvocationType.ScriptFile,
            result.InvocationType);
    }

    [Fact]
    public void Normal_process_is_ignored()
    {
        var result =
            Analyze(
                "notepad.exe",
                "notepad.exe test.txt");

        Assert.Null(result);
    }

    private AlgorithmExecutionAttempt? Analyze(
        string processName,
        string commandLine)
    {
        var signal =
            new ProcessStartSignal(
                100,
                50,
                processName,
                DateTimeOffset.UtcNow);

        var metadata =
            new ProcessMetadata(
                100,
                50,
                processName,
                null,
                commandLine);

        return _analyzer.Analyze(
            signal,
            metadata);
    }

    [Fact]
    public void PowerShell_file_stdin_is_detected()
    {
        var result =
            Analyze(
                "powershell.exe",
                "powershell.exe -File -");

        Assert.NotNull(
            result);

        Assert.Equal(
            AlgorithmInvocationType.StandardInput,
            result.InvocationType);
    }

    [Fact]
    public void Pwsh_command_with_args_is_detected()
    {
        var result =
            Analyze(
                "pwsh.exe",
                """
                pwsh.exe -CommandWithArgs "Get-Process"
                """);

        Assert.NotNull(
            result);

        Assert.Equal(
            AlgorithmInvocationType.InlineCommand,
            result.InvocationType);
    }

    [Fact]
    public void Python_module_is_detected()
    {
        var result =
            Analyze(
                "python.exe",
                "python.exe -m http.server");

        Assert.NotNull(
            result);

        Assert.Equal(
            AlgorithmInvocationType.Module,
            result.InvocationType);

        Assert.Null(
            result.ScriptPath);
    }

    [Fact]
    public void Python_stdin_is_detected()
    {
        var result =
            Analyze(
                "python.exe",
                "python.exe -");

        Assert.NotNull(
            result);

        Assert.Equal(
            AlgorithmInvocationType.StandardInput,
            result.InvocationType);
    }
}