using SecurityGuard.AlgorithmGuard.Enums;

namespace SecurityGuard.AlgorithmGuard.Services;

public sealed class InterpreterCatalog
{
    private static readonly Dictionary<string, InterpreterKind> Interpreters =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["powershell.exe"] = InterpreterKind.PowerShell,
            ["pwsh.exe"] = InterpreterKind.PowerShell,
            ["cmd.exe"] = InterpreterKind.CommandShell,
            ["wscript.exe"] = InterpreterKind.WindowsScriptHost,
            ["cscript.exe"] = InterpreterKind.WindowsScriptHost,
            ["python.exe"] = InterpreterKind.Python,
            ["python3.exe"] = InterpreterKind.Python,
            ["pythonw.exe"] = InterpreterKind.Python
        };

    public bool TryGetInterpreter(
        string processName,
        out InterpreterKind interpreter)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            processName);

        var name =
            Path.GetFileName(processName);

        return Interpreters.TryGetValue(
            name,
            out interpreter);
    }
}