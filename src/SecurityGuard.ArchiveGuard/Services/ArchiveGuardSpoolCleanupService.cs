using SecurityGuard.ArchiveGuard.Configuration;
using SecurityGuard.ArchiveGuard.Contracts;

namespace SecurityGuard.ArchiveGuard.Services;

public sealed class ArchiveGuardSpoolCleanupService
    : IArchiveGuardSpoolCleanupService
{
    private readonly ArchiveGuardOptions _options;

    public ArchiveGuardSpoolCleanupService(
        ArchiveGuardOptions options)
    {
        _options =
            options;
    }

    public async Task<int> CleanupAsync(
        DateTimeOffset olderThanUtc,
        CancellationToken cancellationToken = default)
    {
        var root =
            GetSpoolDirectory();

        if (!Directory.Exists(
                root))
        {
            return 0;
        }

        var deleted =
            0;

        foreach (var filePath in
                 Directory.EnumerateFiles(
                     root,
                     "*.tmp",
                     SearchOption.TopDirectoryOnly))
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                var info =
                    new FileInfo(
                        filePath);

                info.Refresh();

                if (!info.Exists ||
                    info.LastWriteTimeUtc >
                    olderThanUtc.UtcDateTime)
                {
                    continue;
                }

                await using (
                    var lease =
                        new FileStream(
                            filePath,
                            FileMode.Open,
                            FileAccess.ReadWrite,
                            FileShare.None,
                            bufferSize:
                                4096,
                            FileOptions.Asynchronous))
                {
                }

                File.Delete(
                    filePath);

                deleted++;
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        return deleted;
    }

    private string GetSpoolDirectory()
    {
        return !string.IsNullOrWhiteSpace(
                _options.SpoolDirectory)
            ? Path.GetFullPath(
                _options.SpoolDirectory)
            : Path.Combine(
                Path.GetTempPath(),
                "SecurityGuard",
                "ArchiveGuard",
                "Spool");
    }
}