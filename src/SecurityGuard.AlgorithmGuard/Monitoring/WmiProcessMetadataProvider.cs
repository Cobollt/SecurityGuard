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
                    GetNullableInt32(
                        process["ParentProcessId"]);

                var owner =
                    GetOwner(process);

                string? parentName = null;
                string? parentPath = null;

                if (parentProcessId is > 0)
                {
                    var parent =
                        QueryIdentity(
                            parentProcessId.Value);

                    parentName =
                        parent.Name;

                    parentPath =
                        parent.Path;
                }

                return new ProcessMetadata(
                    processId,
                    parentProcessId,
                    Convert.ToString(
                        process["Name"]) ??
                    string.Empty,
                    Convert.ToString(
                        process["ExecutablePath"]),
                    Convert.ToString(
                        process["CommandLine"]),
                    owner,
                    parentName,
                    parentPath);
            }
        }

        return null;
    }

    private static string? GetOwner(
        ManagementObject process)
    {
        ManagementBaseObject? result = null;

        try
        {
            result =
                process.InvokeMethod(
                    "GetOwner",
                    null,
                    null);

            if (result is null)
            {
                return null;
            }

            var returnValue =
                Convert.ToUInt32(
                    result["ReturnValue"]);

            if (returnValue != 0)
            {
                return null;
            }

            var user =
                Convert.ToString(
                    result["User"]);

            var domain =
                Convert.ToString(
                    result["Domain"]);

            if (string.IsNullOrWhiteSpace(
                    user))
            {
                return null;
            }

            if (string.IsNullOrWhiteSpace(
                    domain))
            {
                return user;
            }

            return $@"{domain}\{user}";
        }
        catch
        {
            return null;
        }
        finally
        {
            result?.Dispose();
        }
    }

    private static ProcessIdentity QueryIdentity(
        int processId)
    {
        try
        {
            using var searcher =
                new ManagementObjectSearcher(
                    $"""
                    SELECT
                        Name,
                        ExecutablePath
                    FROM Win32_Process
                    WHERE ProcessId = {processId}
                    """);

            using var results =
                searcher.Get();

            foreach (ManagementObject process in results)
            {
                using (process)
                {
                    return new ProcessIdentity(
                        Convert.ToString(
                            process["Name"]),
                        Convert.ToString(
                            process["ExecutablePath"]));
                }
            }
        }
        catch
        {
        }

        return new ProcessIdentity(
            null,
            null);
    }

    private static int? GetNullableInt32(
        object? value)
    {
        if (value is null)
        {
            return null;
        }

        return Convert.ToInt32(
            value);
    }

    private sealed record ProcessIdentity(
        string? Name,
        string? Path);
}