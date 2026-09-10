using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Contracts;

namespace SecurityGuard.ArchiveGuard.Services;

public sealed class ArchiveGuardFileConsistencyService
    : IArchiveGuardFileConsistencyService
{
    private readonly IFileHashService _fileHashService;

    public ArchiveGuardFileConsistencyService(
        IFileHashService fileHashService)
    {
        _fileHashService =
            fileHashService;
    }

    public async Task<bool> IsConsistentAsync(
        ArchiveFileMetadata metadata,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            metadata);

        try
        {
            if (!File.Exists(
                    metadata.FilePath))
            {
                return false;
            }

            var info =
                new FileInfo(
                    metadata.FilePath);

            info.Refresh();

            if (info.Length !=
                metadata.Length)
            {
                return false;
            }

            var sha256 =
                await _fileHashService.ComputeSha256Async(
                    metadata.FilePath,
                    cancellationToken);

            return string.Equals(
                sha256,
                metadata.Sha256,
                StringComparison.OrdinalIgnoreCase);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return false;
        }
    }
}