using System.Security.Cryptography;
using System.Text;
using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.AlgorithmGuard.Services;

public static class AlgorithmExecutionIdentity
{
    public static string Create(
        AlgorithmExecutionAttempt attempt)
    {
        ArgumentNullException.ThrowIfNull(
            attempt);

        var source =
            string.Join(
                "\n",
                new[]
                {
                    attempt.Interpreter.ToString(),
                    attempt.InvocationType.ToString(),
                    Normalize(attempt.ScriptSha256),
                    Normalize(attempt.ScriptPath),
                    Normalize(attempt.ProcessName),
                    Normalize(attempt.CommandLine),
                    Normalize(attempt.UserName),
                    Normalize(attempt.ParentProcessName),
                    Normalize(attempt.ParentExecutablePath),
                    Normalize(attempt.ProcessPublisher),
                    Normalize(BuildExecutionChain(attempt))
                });

        var bytes =
            Encoding.UTF8.GetBytes(
                source);

        var hash =
            SHA256.HashData(
                bytes);

        return $"ALG:{Convert.ToHexString(hash)}";
    }

    private static string Normalize(
        string? value)
    {
        return string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.Trim().ToUpperInvariant();
    }

    private static string BuildExecutionChain(
        AlgorithmExecutionAttempt attempt)
    {
        var ancestry =
            attempt.ExecutionChain ??
            [];

        return string.Join(
            ">",
            ancestry
                .Reverse()
                .Select(
                    item =>
                        $"{item.ProcessName}|{item.ExecutablePath}")
                .Append(
                    $"{attempt.ProcessName}|{attempt.ExecutablePath}"));
    }
}