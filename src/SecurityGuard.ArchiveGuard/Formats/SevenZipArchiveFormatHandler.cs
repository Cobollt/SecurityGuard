using System.Runtime.CompilerServices;
using SharpCompress.Archives;
using SharpCompress.Common;
using SharpCompress.Readers;
using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Formats;

public sealed class SevenZipArchiveFormatHandler
    : IArchiveFormatHandler
{
    public DetectedFileType FileType =>
        DetectedFileType.SevenZip;

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
                "7z handler requires a seekable stream.");
        }

        stream.Position =
            0;

        using var archive =
            ArchiveFactory.OpenArchive(
                stream,
                ReaderOptions.ForExternalStream);

        foreach (var entry in
                 archive.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var captured =
                entry;

            yield return new ArchiveFormatEntry(
                captured.Key ??
                string.Empty,
                SafeSize(
                    () =>
                        captured.Size),
                SafeSize(
                    () =>
                        captured.CompressedSize),
                captured.IsDirectory,
                captured.IsEncrypted,
                !string.IsNullOrWhiteSpace(
                    captured.LinkTarget),
                captured.LinkTarget,
                ToUtc(
                    captured.LastModifiedTime),
                async token =>
                    await captured.OpenEntryStreamAsync(
                        token));

            await Task.Yield();
        }
    }

    private static long? SafeSize(
        Func<long> getter)
    {
        try
        {
            var value =
                getter();

            return value >= 0
                ? value
                : null;
        }
        catch
        {
            return null;
        }
    }

    private static DateTimeOffset? ToUtc(
        DateTime? value)
    {
        if (value is null)
        {
            return null;
        }

        return new DateTimeOffset(
                value.Value)
            .ToUniversalTime();
    }
}