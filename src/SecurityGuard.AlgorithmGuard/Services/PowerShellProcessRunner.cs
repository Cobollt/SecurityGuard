using System.Diagnostics;
using System.Text;

namespace SecurityGuard.AlgorithmGuard.Services;

public sealed class PowerShellProcessRunner
{
    public async Task<string> RunEncodedAsync(
        string script,
        IReadOnlyDictionary<string, string>? environment = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(script);

        var encoded =
            Convert.ToBase64String(
                Encoding.Unicode.GetBytes(script));

        var startInfo =
            new ProcessStartInfo
            {
                FileName = "powershell.exe",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-EncodedCommand");
        startInfo.ArgumentList.Add(encoded);

        if (environment is not null)
        {
            foreach (var item in environment)
            {
                startInfo.Environment[item.Key] =
                    item.Value;
            }
        }

        using var process =
            new Process
            {
                StartInfo = startInfo
            };

        if (!process.Start())
        {
            throw new InvalidOperationException(
                "Unable to start Windows PowerShell.");
        }

        var outputTask =
            process.StandardOutput.ReadToEndAsync(
                cancellationToken);

        var errorTask =
            process.StandardError.ReadToEndAsync(
                cancellationToken);

        await process.WaitForExitAsync(
            cancellationToken);

        var output =
            await outputTask;

        var error =
            await errorTask;

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                string.IsNullOrWhiteSpace(error)
                    ? $"PowerShell exited with code {process.ExitCode}."
                    : error.Trim());
        }

        return output.Trim();
    }
}