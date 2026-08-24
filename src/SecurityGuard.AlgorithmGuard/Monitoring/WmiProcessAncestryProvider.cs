using System.Management;
using SecurityGuard.AlgorithmGuard.Configuration;
using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.AlgorithmGuard.Monitoring;

public sealed class WmiProcessAncestryProvider
    : IProcessAncestryProvider
{
    private readonly AlgorithmGuardOptions _options;

    public WmiProcessAncestryProvider(
        AlgorithmGuardOptions options)
    {
        _options =
            options;
    }

    public Task<IReadOnlyList<ProcessAncestryEntry>> GetAsync(
        ProcessMetadata process,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            process);

        var results =
            new List<ProcessAncestryEntry>();

        var visited =
            new HashSet<int>();

        var currentParentId =
            process.ParentProcessId;

        var childCreationTime =
            process.CreatedAtUtc;

        for (var depth = 0;
             depth < _options.MaxAncestorDepth;
             depth++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (currentParentId is null ||
                currentParentId <= 0)
            {
                break;
            }

            if (!visited.Add(
                    currentParentId.Value))
            {
                break;
            }

            var parent =
                Query(
                    currentParentId.Value);

            if (parent is null)
            {
                break;
            }

            if (childCreationTime is not null &&
                parent.CreatedAtUtc is not null &&
                parent.CreatedAtUtc >
                childCreationTime)
            {
                break;
            }

            results.Add(
                parent);

            currentParentId =
                parent.ParentProcessId;

            childCreationTime =
                parent.CreatedAtUtc;
        }

        return Task.FromResult<
            IReadOnlyList<ProcessAncestryEntry>>(
            results);
    }

    private static ProcessAncestryEntry? Query(
        int processId)
    {
        try
        {
            using var searcher =
                new ManagementObjectSearcher(
                    $"""
                    SELECT
                        ProcessId,
                        ParentProcessId,
                        Name,
                        ExecutablePath,
                        CreationDate
                    FROM Win32_Process
                    WHERE ProcessId = {processId}
                    """);

            using var results =
                searcher.Get();

            foreach (ManagementObject process in results)
            {
                using (process)
                {
                    return new ProcessAncestryEntry(
                        Convert.ToInt32(
                            process["ProcessId"]),
                        GetNullableInt32(
                            process["ParentProcessId"]),
                        Convert.ToString(
                            process["Name"]) ??
                        string.Empty,
                        Convert.ToString(
                            process["ExecutablePath"]),
                        GetCreationTime(
                            process["CreationDate"]));
                }
            }
        }
        catch
        {
        }

        return null;
    }

    private static int? GetNullableInt32(
        object? value)
    {
        return value is null
            ? null
            : Convert.ToInt32(
                value);
    }

    private static DateTimeOffset? GetCreationTime(
        object? value)
    {
        var text =
            Convert.ToString(
                value);

        if (string.IsNullOrWhiteSpace(
                text))
        {
            return null;
        }

        try
        {
            var valueDate =
                ManagementDateTimeConverter.ToDateTime(
                    text);

            return new DateTimeOffset(
                valueDate.ToUniversalTime());
        }
        catch
        {
            return null;
        }
    }
}