using System.IO.Compression;
using System.Runtime.CompilerServices;
using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Formats;

public sealed class ZipArchiveFormatHandler
    : IArchiveFormatHandler
{
    public DetectedFileType FileType =>
        DetectedFileType.Zip;

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
                "ZIP handler requires a seekable stream.");
        }

        stream.Position =
            0;

        using var archive =
            new ZipArchive(
                stream,
                ZipArchiveMode.Read,
                leaveOpen:
                    true);

        foreach (var entry in
                 archive.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var captured =
                entry;

            yield return new ArchiveFormatEntry(
                captured.FullName,
                captured.Length,
                captured.CompressedLength,
                string.IsNullOrEmpty(
                    captured.Name),
                captured.IsEncrypted,
                false,
                null,
                captured.LastWriteTime.ToUniversalTime(),
                token =>
                {
                    token.ThrowIfCancellationRequested();

                    return ValueTask.FromResult<Stream>(
                        captured.Open());
                });

            await Task.Yield();
        }
    }
}