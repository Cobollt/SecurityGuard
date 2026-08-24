using System.Security.Cryptography;
using System.Text;
using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.AlgorithmGuard.Services;

public static class AlgorithmExecutionChainId
{
    public static Guid Create(
        ProcessMetadata process,
        IReadOnlyList<ProcessAncestryEntry> ancestors,
        InterpreterCatalog catalog)
    {
        ArgumentNullException.ThrowIfNull(
            process);

        ArgumentNullException.ThrowIfNull(
            ancestors);

        ArgumentNullException.ThrowIfNull(
            catalog);

        var anchor =
            ancestors
                .Where(
                    item =>
                        catalog.TryGetInterpreter(
                            item.ProcessName,
                            out _))
                .LastOrDefault();

        var processId =
            anchor?.ProcessId ??
            process.ProcessId;

        var processName =
            anchor?.ProcessName ??
            process.ProcessName;

        var executable =
            anchor?.ExecutablePath ??
            process.ExecutablePath;

        var createdAt =
            anchor?.CreatedAtUtc ??
            process.CreatedAtUtc;

        var source =
            string.Join(
                "\n",
                processId.ToString(),
                processName,
                executable ?? string.Empty,
                createdAt?.ToString("O") ??
                string.Empty);

        var hash =
            SHA256.HashData(
                Encoding.UTF8.GetBytes(
                    source));

        return new Guid(
            hash.AsSpan(
                0,
                16));
    }
}