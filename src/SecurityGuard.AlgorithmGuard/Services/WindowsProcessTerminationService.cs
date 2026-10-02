using System.ComponentModel;
using System.Diagnostics;
using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.AlgorithmGuard.Services;

public sealed class WindowsProcessTerminationService
    : IProcessTerminationService
{
    public Task<ProcessTerminationResult> TerminateAsync(
        int processId,
        string? expectedProcessName,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (processId <= 0)
        {
            return Task.FromResult(
                new ProcessTerminationResult(
                    false,
                    "Invalid process identifier."));
        }

        Process process;

        try
        {
            process =
                Process.GetProcessById(
                    processId);
        }
        catch (ArgumentException)
        {
            return Task.FromResult(
                new ProcessTerminationResult(
                    false,
                    "Process has already exited."));
        }

        using (process)
        {
            try
            {
                if (process.HasExited)
                {
                    return Task.FromResult(
                        new ProcessTerminationResult(
                            false,
                            "Process has already exited."));
                }

                if (!string.IsNullOrWhiteSpace(
                        expectedProcessName))
                {
                    var expected =
                        Path.GetFileNameWithoutExtension(
                            expectedProcessName);

                    if (!string.Equals(
                            process.ProcessName,
                            expected,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        return Task.FromResult(
                            new ProcessTerminationResult(
                                false,
                                "Process identity changed before termination."));
                    }
                }

                process.Kill(
                    entireProcessTree: true);

                return Task.FromResult(
                    new ProcessTerminationResult(
                        true,
                        "Blocked algorithm process was terminated."));
            }
            catch (InvalidOperationException)
            {
                return Task.FromResult(
                    new ProcessTerminationResult(
                        false,
                        "Process has already exited."));
            }
            catch (Win32Exception exception)
            {
                return Task.FromResult(
                    new ProcessTerminationResult(
                        false,
                        exception.Message));
            }
        }
    }
}