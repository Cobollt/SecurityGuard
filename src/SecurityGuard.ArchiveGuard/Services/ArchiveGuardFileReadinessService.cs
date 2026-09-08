using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Services;

public sealed class ArchiveGuardFileReadinessService
    : IArchiveGuardFileReadinessService
{
    public async Task<bool> WaitUntilStableAsync(
        string filePath,
        ArchiveGuardAutoScanSettings settings,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            filePath);

        ArgumentNullException.ThrowIfNull(
            settings);

        var deadline =
            DateTimeOffset.UtcNow +
            TimeSpan.FromSeconds(
                settings.ReadyTimeoutSeconds);

        long? previousLength =
            null;

        DateTime? previousWriteTime =
            null;

        var stableChecks =
            0;

        while (DateTimeOffset.UtcNow <
               deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!File.Exists(
                    filePath))
            {
                return false;
            }

            try
            {
                var info =
                    new FileInfo(
                        filePath);

                info.Refresh();

                await using var stream =
                    new FileStream(
                        filePath,
                        FileMode.Open,
                        FileAccess.Read,
                        FileShare.Read |
                        FileShare.Delete,
                        bufferSize:
                            4096,
                        FileOptions.Asynchronous |
                        FileOptions.SequentialScan);

                if (previousLength ==
                        info.Length &&
                    previousWriteTime ==
                        info.LastWriteTimeUtc)
                {
                    stableChecks++;
                }
                else
                {
                    previousLength =
                        info.Length;

                    previousWriteTime =
                        info.LastWriteTimeUtc;

                    stableChecks =
                        1;
                }

                if (stableChecks >=
                    settings.StabilityCheckCount)
                {
                    return true;
                }
            }
            catch (IOException)
            {
                stableChecks =
                    0;
            }
            catch (UnauthorizedAccessException)
            {
                stableChecks =
                    0;
            }

            await Task.Delay(
                settings.StabilityCheckIntervalMilliseconds,
                cancellationToken);
        }

        return false;
    }
}