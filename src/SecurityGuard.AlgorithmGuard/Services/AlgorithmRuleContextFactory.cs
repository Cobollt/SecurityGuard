using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.Core.Models;

namespace SecurityGuard.AlgorithmGuard.Services;

public sealed class AlgorithmRuleContextFactory
{
    public RuleMatchContext Create(
        AlgorithmExecutionAttempt attempt)
    {
        ArgumentNullException.ThrowIfNull(
            attempt);

        string? fileName = null;
        string? extension = null;

        if (!string.IsNullOrWhiteSpace(
                attempt.ScriptPath))
        {
            fileName =
                Path.GetFileName(
                    attempt.ScriptPath);

            extension =
                Path.GetExtension(
                    attempt.ScriptPath);
        }

        var ancestry =
            attempt.ExecutionChain ??
            [];

        var root =
            ancestry.LastOrDefault();

        return new RuleMatchContext(
            FileHash:
                attempt.ScriptSha256,

            FilePath:
                attempt.ScriptPath,

            FileName:
                fileName,

            FileExtension:
                extension,

            Publisher:
                attempt.ScriptPublisher ??
                attempt.ProcessPublisher,

            Process:
                attempt.ProcessName,

            ParentProcess:
                attempt.ParentProcessName,

            Interpreter:
                attempt.Interpreter.ToString(),

            CommandLine:
                attempt.CommandLine,

            UserName:
                attempt.UserName,

            ProcessPublisher:
                attempt.ProcessPublisher,

            ParentProcessPath:
                attempt.ParentExecutablePath,

            RootProcess:
                root?.ProcessName,

            RootProcessPath:
                root?.ExecutablePath,

            ExecutionChain:
                BuildExecutionChain(
                    attempt));
    }

    private static string BuildExecutionChain(
        AlgorithmExecutionAttempt attempt)
    {
        var ancestors =
            attempt.ExecutionChain ??
            [];

        var names =
            ancestors
                .Reverse()
                .Select(
                    item =>
                        item.ProcessName)
                .Append(
                    attempt.ProcessName);

        return string.Join(
            " > ",
            names);
    }
}