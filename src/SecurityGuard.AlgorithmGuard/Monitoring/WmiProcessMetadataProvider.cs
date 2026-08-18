using System.Management;
using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.AlgorithmGuard.Monitoring;

public sealed class WmiProcessMetadataProvider
    : IProcessMetadataProvider
{
    public async Task<ProcessMetadata?> GetAsync(
        int processId,
        CancellationToken cancellationToken = default)
    {
        if (processId <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(processId));
        }

        for (var attempt = 0;
             attempt < 3;
             attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var result =
                Query(processId);

            if (result is not null)
            {
                return result;
            }

            await Task.Delay(
                25,
                cancellationToken);
        }

        return null;
    }

    private static ProcessMetadata? Query(
        int processId)
    {
        using var searcher =
            new ManagementObjectSearcher(
                $"""
                SELECT
                    ProcessId,
                    ParentProcessId,
                    Name,
                    ExecutablePath,
                    CommandLine
                FROM Win32_Process
                WHERE ProcessId = {processId}
                """);

        using var results =
            searcher.Get();

        foreach (ManagementObject process in results)
        {
            using (process)
            {
                var parentProcessId =
                    process["ParentProcessId"] is null
                        ? null
                        : Convert.ToInt32(
                            process["ParentProcessId"]);

                return new ProcessMetadata(
                    processId,
                    parentProcessId,
                    Convert.ToString(
                        process["Name"]) ??
                    string.Empty,
                    Convert.ToString(
                        process["ExecutablePath"]),
                    Convert.ToString(
                        process["CommandLine"]));
            }
        }

        return null;
    }
}