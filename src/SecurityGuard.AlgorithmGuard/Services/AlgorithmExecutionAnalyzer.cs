using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Enums;
using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.AlgorithmGuard.Parsing;

namespace SecurityGuard.AlgorithmGuard.Services;

public sealed class AlgorithmExecutionAnalyzer
    : IAlgorithmExecutionAnalyzer
{
    private readonly InterpreterCatalog _catalog;
    private readonly WindowsCommandLineParser _commandLineParser;

    public AlgorithmExecutionAnalyzer(
        InterpreterCatalog catalog,
        WindowsCommandLineParser commandLineParser)
    {
        _catalog = catalog;
        _commandLineParser = commandLineParser;
    }

    public AlgorithmExecutionAttempt? Analyze(
        ProcessStartSignal signal,
        ProcessMetadata metadata)
    {
        if (!_catalog.TryGetInterpreter(
                metadata.ProcessName,
                out var interpreter))
        {
            return null;
        }

        IReadOnlyList<string> arguments = [];

        if (!string.IsNullOrWhiteSpace(
                metadata.CommandLine))
        {
            try
            {
                arguments =
                    _commandLineParser.Parse(
                        metadata.CommandLine);
            }
            catch
            {
                arguments = [];
            }
        }

        var analysis =
            AnalyzeArguments(
                interpreter,
                arguments);

        return new AlgorithmExecutionAttempt(
            Guid.NewGuid(),
            metadata.ProcessId,
            metadata.ParentProcessId,
            metadata.ProcessName,
            metadata.ExecutablePath,
            metadata.CommandLine,
            interpreter,
            analysis.Type,
            analysis.ScriptPath,
            null,
            signal.DetectedAtUtc,
            metadata.UserName,
            metadata.ParentProcessName,
            metadata.ParentExecutablePath);
    }

    private static InvocationAnalysis AnalyzeArguments(
        InterpreterKind interpreter,
        IReadOnlyList<string> arguments)
    {
        if (arguments.Count <= 1)
        {
            return new InvocationAnalysis(
                AlgorithmInvocationType.Unknown,
                null);
        }

        return interpreter switch
        {
            InterpreterKind.PowerShell =>
                AnalyzePowerShell(arguments),

            InterpreterKind.CommandShell =>
                AnalyzeCommandShell(arguments),

            InterpreterKind.WindowsScriptHost =>
                AnalyzeWindowsScriptHost(arguments),

            InterpreterKind.Python =>
                AnalyzePython(arguments),

            _ =>
                new InvocationAnalysis(
                    AlgorithmInvocationType.Unknown,
                    null)
        };
    }

    private static InvocationAnalysis AnalyzePowerShell(
        IReadOnlyList<string> arguments)
    {
        for (var index = 1;
             index < arguments.Count;
             index++)
        {
            var argument =
                arguments[index];

            if (Matches(
                    argument,
                    "-EncodedCommand",
                    "-Enc"))
            {
                return new InvocationAnalysis(
                    AlgorithmInvocationType.EncodedCommand,
                    null);
            }

            if (Matches(
                    argument,
                    "-Command",
                    "-C"))
            {
                return new InvocationAnalysis(
                    AlgorithmInvocationType.InlineCommand,
                    null);
            }

            if (Matches(
                    argument,
                    "-File") &&
                index + 1 < arguments.Count)
            {
                return new InvocationAnalysis(
                    AlgorithmInvocationType.ScriptFile,
                    NormalizeScriptPath(
                        arguments[index + 1]));
            }

            if (HasExtension(
                    argument,
                    ".ps1"))
            {
                return new InvocationAnalysis(
                    AlgorithmInvocationType.ScriptFile,
                    NormalizeScriptPath(argument));
            }
        }

        return new InvocationAnalysis(
            AlgorithmInvocationType.Unknown,
            null);
    }

    private static InvocationAnalysis AnalyzeCommandShell(
        IReadOnlyList<string> arguments)
    {
        for (var index = 1;
             index < arguments.Count;
             index++)
        {
            if (!Matches(
                    arguments[index],
                    "/C",
                    "/K"))
            {
                continue;
            }

            if (index + 1 >= arguments.Count)
            {
                return new InvocationAnalysis(
                    AlgorithmInvocationType.InlineCommand,
                    null);
            }

            var next =
                arguments[index + 1];

            if (HasExtension(
                    next,
                    ".cmd",
                    ".bat"))
            {
                return new InvocationAnalysis(
                    AlgorithmInvocationType.ScriptFile,
                    NormalizeScriptPath(next));
            }

            return new InvocationAnalysis(
                AlgorithmInvocationType.InlineCommand,
                null);
        }

        return new InvocationAnalysis(
            AlgorithmInvocationType.Unknown,
            null);
    }

    private static InvocationAnalysis AnalyzeWindowsScriptHost(
        IReadOnlyList<string> arguments)
    {
        for (var index = 1;
             index < arguments.Count;
             index++)
        {
            var argument =
                arguments[index];

            if (argument.StartsWith(
                    "//",
                    StringComparison.Ordinal))
            {
                continue;
            }

            if (HasExtension(
                    argument,
                    ".vbs",
                    ".js",
                    ".wsf"))
            {
                return new InvocationAnalysis(
                    AlgorithmInvocationType.ScriptFile,
                    NormalizeScriptPath(argument));
            }
        }

        return new InvocationAnalysis(
            AlgorithmInvocationType.Unknown,
            null);
    }

    private static InvocationAnalysis AnalyzePython(
        IReadOnlyList<string> arguments)
    {
        for (var index = 1;
             index < arguments.Count;
             index++)
        {
            var argument =
                arguments[index];

            if (string.Equals(
                    argument,
                    "-c",
                    StringComparison.OrdinalIgnoreCase))
            {
                return new InvocationAnalysis(
                    AlgorithmInvocationType.InlineCommand,
                    null);
            }

            if (HasExtension(
                    argument,
                    ".py",
                    ".pyw"))
            {
                return new InvocationAnalysis(
                    AlgorithmInvocationType.ScriptFile,
                    NormalizeScriptPath(argument));
            }
        }

        return new InvocationAnalysis(
            AlgorithmInvocationType.Unknown,
            null);
    }

    private static bool Matches(
        string value,
        params string[] candidates)
    {
        return candidates.Any(
            candidate =>
                string.Equals(
                    value,
                    candidate,
                    StringComparison.OrdinalIgnoreCase));
    }

    private static bool HasExtension(
        string path,
        params string[] extensions)
    {
        var extension =
            Path.GetExtension(path);

        return extensions.Any(
            candidate =>
                string.Equals(
                    extension,
                    candidate,
                    StringComparison.OrdinalIgnoreCase));
    }

    private static string NormalizeScriptPath(
        string path)
    {
        if (!Path.IsPathRooted(path))
        {
            return path;
        }

        try
        {
            return Path.GetFullPath(path);
        }
        catch
        {
            return path;
        }
    }

    private sealed record InvocationAnalysis(
        AlgorithmInvocationType Type,
        string? ScriptPath);
}