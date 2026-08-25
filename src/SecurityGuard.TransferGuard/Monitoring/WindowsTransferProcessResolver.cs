using System.Diagnostics;
using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Contracts;

namespace SecurityGuard.TransferGuard.Monitoring;

public sealed class WindowsTransferProcessResolver
    : ITransferProcessResolver
{
    public Task<ProcessInfo?> GetAsync(
        int processId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (processId <= 0)
        {
            return Task.FromResult<ProcessInfo?>(
                null);
        }

        try
        {
            using var process =
                Process.GetProcessById(
                    processId);

            string processName;

            try
            {
                processName =
                    process.ProcessName;
            }
            catch
            {
                processName =
                    $"PID-{processId}";
            }

            string executablePath =
                string.Empty;

            try
            {
                executablePath =
                    process.MainModule?.FileName ??
                    string.Empty;
            }
            catch
            {
            }

            var result =
                new ProcessInfo(
                    processId,
                    null,
                    processName,
                    executablePath,
                    null,
                    null,
                    null);

            return Task.FromResult<ProcessInfo?>(
                result);
        }
        catch
        {
            return Task.FromResult<ProcessInfo?>(
                null);
        }
    }
}