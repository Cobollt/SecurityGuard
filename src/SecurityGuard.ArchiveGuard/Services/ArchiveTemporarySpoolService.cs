using SecurityGuard.ArchiveGuard.Configuration;
using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Services;

public sealed class ArchiveTemporarySpoolService
    : IArchiveTemporarySpoolService
{
    private readonly ArchiveGuardOptions _options;

    public ArchiveTemporarySpoolService(
        ArchiveGuardOptions options)
    {
        _options =
            options;
    }

    public Task<ArchiveTemporarySpool> CreateAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var root =
            !string.IsNullOrWhiteSpace(
                _options.SpoolDirectory)
                ? Path.GetFullPath(
                    _options.SpoolDirectory)
                : Path.Combine(
                    Path.GetTempPath(),
                    "SecurityGuard",
                    "ArchiveGuard",
                    "Spool");

        Directory.CreateDirectory(
            root);

        for (var attempt = 0;
             attempt < 16;
             attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var path =
                Path.Combine(
                    root,
                    $"{Guid.NewGuid():N}.tmp");

            try
            {
                var stream =
                    new FileStream(
                        path,
                        FileMode.CreateNew,
                        FileAccess.ReadWrite,
                        FileShare.None,
                        bufferSize:
                            64 * 1024,
                        FileOptions.Asynchronous |
                        FileOptions.DeleteOnClose);

                return Task.FromResult(
                    new ArchiveTemporarySpool(
                        path,
                        stream));
            }
            catch (IOException)
            {
            }
        }

        throw new IOException(
            "Unable to create ArchiveGuard temporary spool.");
    }
}