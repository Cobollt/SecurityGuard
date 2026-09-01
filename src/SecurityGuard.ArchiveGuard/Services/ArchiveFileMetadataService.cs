using SecurityGuard.ArchiveGuard.Configuration;
using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Contracts;

namespace SecurityGuard.ArchiveGuard.Services;

public sealed class ArchiveFileMetadataService
    : IArchiveFileMetadataService
{
    private readonly IFileHashService _fileHashService;
    private readonly ArchiveGuardOptions _options;

    public ArchiveFileMetadataService(
        IFileHashService fileHashService,
        ArchiveGuardOptions options)
    {
        _fileHashService =
            fileHashService;

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
            header);
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
                    4096,
                FileOptions.Asynchronous |
                FileOptions.SequentialScan);

        var read =
            await stream.ReadAsync(
                buffer,
                cancellationToken);

        if (read ==
            buffer.Length)
        {
            return buffer;
        }

        return buffer[..read];
    }
}