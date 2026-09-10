using SecurityGuard.ArchiveGuard.Configuration;
using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Exceptions;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Contracts;

namespace SecurityGuard.ArchiveGuard.Services;

public sealed class ArchiveFileMetadataService
    : IArchiveFileMetadataService
{
    private readonly IFileHashService _fileHashService;
    private readonly IFileTypeDetector _fileTypeDetector;
    private readonly ArchiveGuardOptions _options;

    public ArchiveFileMetadataService(
        IFileHashService fileHashService,
        IFileTypeDetector fileTypeDetector,
        ArchiveGuardOptions options)
    {
        _fileHashService =
            fileHashService;

        _fileTypeDetector =
            fileTypeDetector;

        _options =
            options;
    }

    public async Task<ArchiveFileMetadata> LoadAsync(
        string filePath,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            filePath);

        var fullPath =
            Path.GetFullPath(
                filePath);

        if (!File.Exists(
                fullPath))
        {
            throw new FileNotFoundException(
                "File was not found.",
                fullPath);
        }

        ArchiveFileChangedException? lastMutation =
            null;

        for (var attempt = 0;
             attempt <=
             _options.MaxFileMutationRetries;
             attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                return await LoadStableAsync(
                    fullPath,
                    cancellationToken);
            }
            catch (ArchiveFileChangedException exception)
            {
                lastMutation =
                    exception;

                if (attempt >=
                    _options.MaxFileMutationRetries)
                {
                    throw;
                }

                await Task.Delay(
                    _options.FileMutationRetryDelayMilliseconds,
                    cancellationToken);
            }
        }

        throw lastMutation ??
              new ArchiveFileChangedException(
                  fullPath);
    }

    private async Task<ArchiveFileMetadata> LoadStableAsync(
        string fullPath,
        CancellationToken cancellationToken)
    {
        var before =
            new FileInfo(
                fullPath);

        before.Refresh();

        if (!before.Exists)
        {
            throw new FileNotFoundException(
                "File was not found.",
                fullPath);
        }

        var lengthBefore =
            before.Length;

        var writeBefore =
            before.LastWriteTimeUtc;

        var headerBefore =
            await ReadHeaderAsync(
                fullPath,
                cancellationToken);

        var sha256 =
            await _fileHashService.ComputeSha256Async(
                fullPath,
                cancellationToken);

        var headerAfter =
            await ReadHeaderAsync(
                fullPath,
                cancellationToken);

        var after =
            new FileInfo(
                fullPath);

        after.Refresh();

        if (!after.Exists ||
            lengthBefore !=
                after.Length ||
            writeBefore !=
                after.LastWriteTimeUtc ||
            !headerBefore.AsSpan()
                .SequenceEqual(
                    headerAfter))
        {
            throw new ArchiveFileChangedException(
                fullPath);
        }

        var fileType =
            _fileTypeDetector.Detect(
                headerAfter);

        return new ArchiveFileMetadata(
            after.FullName,
            after.Name,
            after.Extension,
            after.Length,
            new DateTimeOffset(
                after.LastWriteTimeUtc,
                TimeSpan.Zero),
            sha256.ToUpperInvariant(),
            headerAfter,
            fileType);
    }

    private async Task<byte[]> ReadHeaderAsync(
        string filePath,
        CancellationToken cancellationToken)
    {
        var buffer =
            new byte[
                _options.HeaderBytesToRead];

        await using var stream =
            new FileStream(
                filePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize:
                    8192,
                FileOptions.Asynchronous |
                FileOptions.SequentialScan);

        var totalRead =
            0;

        while (totalRead <
               buffer.Length)
        {
            var read =
                await stream.ReadAsync(
                    buffer.AsMemory(
                        totalRead,
                        buffer.Length -
                        totalRead),
                    cancellationToken);

            if (read == 0)
            {
                break;
            }

            totalRead +=
                read;
        }

        return totalRead ==
               buffer.Length
            ? buffer
            : buffer[..totalRead];
    }
}