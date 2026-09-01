using SecurityGuard.ArchiveGuard.Configuration;
using SecurityGuard.ArchiveGuard.Contracts;
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

        var info =
            new FileInfo(
                fullPath);

        var header =
            await ReadHeaderAsync(
                fullPath,
                cancellationToken);

        var fileType =
            _fileTypeDetector.Detect(
                header);

        var sha256 =
            await _fileHashService.ComputeSha256Async(
                fullPath,
                cancellationToken);

        info.Refresh();

        return new ArchiveFileMetadata(
            info.FullName,
            info.Name,
            info.Extension,
            info.Length,
            new DateTimeOffset(
                info.LastWriteTimeUtc,
                TimeSpan.Zero),
            sha256.ToUpperInvariant(),
            header,
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

        if (totalRead ==
            buffer.Length)
        {
            return buffer;
        }

        return buffer[..totalRead];
    }
}