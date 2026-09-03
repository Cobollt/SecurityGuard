using System.IO.Compression;
using System.Runtime.CompilerServices;
using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Formats;

public sealed class GzipArchiveFormatHandler
    : IArchiveFormatHandler
{
    public DetectedFileType FileType =>
        DetectedFileType.Gzip;

    public bool RequiresSeekableInput =>
        true;

    public async IAsyncEnumerable<ArchiveFormatEntry> ReadEntriesAsync(
        Stream stream,
        string logicalName,
        [EnumeratorCancellation]
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            stream);

        if (!stream.CanSeek)
        {
            throw new InvalidOperationException(
                "GZIP handler requires a seekable stream.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        var compressedLength =
            stream.Length;

        var entryName =
            DeriveEntryName(
                logicalName);

        yield return new ArchiveFormatEntry(
            entryName,
            null,
            compressedLength,
            false,
            false,
            false,
            null,
            null,
            token =>
            {
                token.ThrowIfCancellationRequested();

                stream.Position =
                    0;

                return ValueTask.FromResult<Stream>(
                    new GZipStream(
                        stream,
                        CompressionMode.Decompress,
                        leaveOpen:
                            true));
            });

        await Task.CompletedTask;
    }

    private static string DeriveEntryName(
        string logicalName)
    {
        if (logicalName.EndsWith(
                ".tar.gz",
                StringComparison.OrdinalIgnoreCase))
        {
            return logicalName[..^3];
        }

        if (logicalName.EndsWith(
                ".tgz",
                StringComparison.OrdinalIgnoreCase))
        {
            return logicalName[..^4] +
                   ".tar";
        }

        if (logicalName.EndsWith(
                ".gzip",
                StringComparison.OrdinalIgnoreCase))
        {
            return logicalName[..^5];
        }

        if (logicalName.EndsWith(
                ".gz",
                StringComparison.OrdinalIgnoreCase))
        {
            return logicalName[..^3];
        }

        return logicalName +
               ".decompressed";
    }
}