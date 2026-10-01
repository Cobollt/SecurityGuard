using System.Diagnostics;
using System.Text;
using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.AlgorithmGuard.Services;

public sealed class AppLockerHealthService
    : IAppLockerHealthService
{
    public async Task<AppLockerHealthSnapshot> GetHealthAsync(
        CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new AppLockerHealthSnapshot(
                false,
                false,
                false,
                false,
                false,
                false,
                false,
                false,
                "AppLocker is available only on Windows.");
        }

        var engine =
            await GetDriverStateAsync(
                "AppID",
                cancellationToken);

        var applicationIdentity =
            await GetServiceStateAsync(
                "AppIDSvc",
                cancellationToken);

        var powerShell =
            await RunProcessAsync(
                "powershell.exe",
                "-NoProfile -NonInteractive -Command \"$PSVersionTable.PSVersion.ToString()\"",
                cancellationToken);

        var powerShellAvailable =
            powerShell.Started &&
            powerShell.ExitCode == 0;

        if (!powerShellAvailable)
        {
            return new AppLockerHealthSnapshot(
                true,
                engine.Installed,
                engine.Running,
                applicationIdentity.Installed,
                applicationIdentity.Running,
                false,
                false,
                false,
                NormalizeError(
                    powerShell,
                    "Windows PowerShell is unavailable."));
        }

        var cmdletCheck =
            await RunPowerShellAsync(
                "$command = Get-Command Get-AppLockerPolicy -ErrorAction SilentlyContinue; if ($null -eq $command) { exit 10 }; exit 0",
                cancellationToken);

        var managementCmdletsAvailable =
            cmdletCheck.Started &&
            cmdletCheck.ExitCode == 0;

        if (!managementCmdletsAvailable)
        {
            return new AppLockerHealthSnapshot(
                true,
                engine.Installed,
                engine.Running,
                applicationIdentity.Installed,
                applicationIdentity.Running,
                true,
                false,
                false,
                "AppLocker engine is available, but AppLocker management cmdlets are unavailable.");
        }

        var policyCheck =
            await RunPowerShellAsync(
                "try { $null = Get-AppLockerPolicy -Effective -ErrorAction Stop; exit 0 } catch { [Console]::Error.Write($_.Exception.Message); exit 11 }",
                cancellationToken);

        var policyReadable =
            policyCheck.Started &&
            policyCheck.ExitCode == 0;

        return new AppLockerHealthSnapshot(
            true,
            engine.Installed,
            engine.Running,
            applicationIdentity.Installed,
            applicationIdentity.Running,
            true,
            true,
            policyReadable,
            policyReadable
                ? null
                : NormalizeError(
                    policyCheck,
                    "AppLocker policy cannot be read."));
    }

    public async Task<AppLockerHealthSnapshot> EnsureReadyAsync(
        CancellationToken cancellationToken = default)
    {
        var current =
            await GetHealthAsync(
                cancellationToken);

        if (!current.IsWindows ||
            !current.ApplicationIdentityInstalled)
        {
            return current;
        }

        if (!current.ApplicationIdentityRunning)
        {
            var startResult =
                await RunProcessAsync(
                    "sc.exe",
                    "start AppIDSvc",
                    cancellationToken);

            if (!startResult.Started ||
                (startResult.ExitCode != 0 &&
                 startResult.ExitCode != 1056))
            {
                return current with
                {
                    Error =
                        NormalizeError(
                            startResult,
                            "Application Identity service could not be started.")
                };
            }

            await WaitForServiceAsync(
                "AppIDSvc",
                cancellationToken);
        }

        return await GetHealthAsync(
            cancellationToken);
    }

    private static async Task<SystemComponentState> GetDriverStateAsync(
        string name,
        CancellationToken cancellationToken)
    {
        var result =
            await RunProcessAsync(
                "sc.exe",
                $"query {name}",
                cancellationToken);

        if (!result.Started)
        {
            return new SystemComponentState(
                false,
                false);
        }

        if (result.ExitCode == 1060 ||
            result.StandardOutput.Contains(
                "1060",
                StringComparison.OrdinalIgnoreCase))
        {
            return new SystemComponentState(
                false,
                false);
        }

        if (result.ExitCode != 0)
        {
            return new SystemComponentState(
                false,
                false);
        }

        var running =
            result.StandardOutput.Contains(
                "RUNNING",
                StringComparison.OrdinalIgnoreCase);

        return new SystemComponentState(
            true,
            running);
    }

    private static async Task<SystemComponentState> GetServiceStateAsync(
        string name,
        CancellationToken cancellationToken)
    {
        var result =
            await RunProcessAsync(
                "sc.exe",
                $"query {name}",
                cancellationToken);

        if (!result.Started)
        {
            return new SystemComponentState(
                false,
                false);
        }

        if (result.ExitCode == 1060 ||
            result.StandardOutput.Contains(
                "1060",
                StringComparison.OrdinalIgnoreCase))
        {
            return new SystemComponentState(
                false,
                false);
        }

        if (result.ExitCode != 0)
        {
            return new SystemComponentState(
                false,
                false);
        }

        var running =
            result.StandardOutput.Contains(
                "RUNNING",
                StringComparison.OrdinalIgnoreCase);

        return new SystemComponentState(
            true,
            running);
    }

    private static async Task WaitForServiceAsync(
        string name,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0;
             attempt < 10;
             attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var state =
                await GetServiceStateAsync(
                    name,
                    cancellationToken);

            if (state.Running)
            {
                return;
            }

            await Task.Delay(
                500,
                cancellationToken);
        }
    }

    private static Task<ProcessResult> RunPowerShellAsync(
        string command,
        CancellationToken cancellationToken)
    {
        var encoded =
            Convert.ToBase64String(
                Encoding.Unicode.GetBytes(
                    command));

        return RunProcessAsync(
            "powershell.exe",
            $"-NoProfile -NonInteractive -EncodedCommand {encoded}",
            cancellationToken);
    }

    private static async Task<ProcessResult> RunProcessAsync(
        string fileName,
        string arguments,
        CancellationToken cancellationToken)
    {
        try
        {
            using var process =
                new Process
                {
                    StartInfo =
                        new ProcessStartInfo
                        {
                            FileName =
                                fileName,
                            Arguments =
                                arguments,
                            UseShellExecute =
                                false,
                            CreateNoWindow =
                                true,
                            RedirectStandardOutput =
                                true,
                            RedirectStandardError =
                                true
                        }
                };

            if (!process.Start())
            {
                return new ProcessResult(
                    false,
                    -1,
                    string.Empty,
                    "Process could not be started.");
            }

            var outputTask =
                process.StandardOutput.ReadToEndAsync(
                    cancellationToken);

            var errorTask =
                process.StandardError.ReadToEndAsync(
                    cancellationToken);

            await process.WaitForExitAsync(
                cancellationToken);

            return new ProcessResult(
                true,
                process.ExitCode,
                await outputTask,
                await errorTask);
        }
        catch (Exception ex)
        {
            return new ProcessResult(
                false,
                -1,
                string.Empty,
                ex.Message);
        }
    }

    private static string NormalizeError(
        ProcessResult result,
        string fallback)
    {
        if (!string.IsNullOrWhiteSpace(
                result.StandardError))
        {
            return result.StandardError.Trim();
        }

        if (!string.IsNullOrWhiteSpace(
                result.StandardOutput))
        {
            return result.StandardOutput.Trim();
        }

        return fallback;
    }

    private sealed record ProcessResult(
        bool Started,
        int ExitCode,
        string StandardOutput,
        string StandardError);

    private sealed record SystemComponentState(
        bool Installed,
        bool Running);
}