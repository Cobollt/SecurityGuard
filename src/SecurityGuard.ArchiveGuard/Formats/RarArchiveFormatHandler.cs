using System.Runtime.CompilerServices;
using SharpCompress.Readers;
using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Formats;

public sealed class RarArchiveFormatHandler
    : IArchiveFormatHandler
{
    public DetectedFileType FileType =>
        DetectedFileType.Rar;

    public bool RequiresSeekableInput =>
        false;

    public async IAsyncEnumerable<ArchiveFormatEntry> ReadEntriesAsync(
        Stream stream,
        string logicalName,
        [EnumeratorCancellation]
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            stream);

        using var reader =
            ReaderFactory.OpenReader(
                stream);

        while (reader.MoveToNextEntry())
        {
            cancellationToken.ThrowIfCancellationRequested();

            var entry =
                reader.Entry;

            var name =
                entry.Key ??
                string.Empty;

            var expanded =
                SafeSize(
                    () =>
                        entry.Size);

            var compressed =
                SafeSize(
                    () =>
                        entry.CompressedSize);

            var encrypted =
                entry.IsEncrypted;

            var directory =
                entry.IsDirectory;

            var linkTarget =
                entry.LinkTarget;

            yield return new ArchiveFormatEntry(
                name,
                expanded,
                compressed,
                directory,
                encrypted,
                !string.IsNullOrWhiteSpace(
                    linkTarget),
                linkTarget,
                ToUtc(
                    entry.LastModifiedTime),
                token =>
                {
                    token.ThrowIfCancellationRequested();

                    return ValueTask.FromResult(
                        reader.OpenEntryStream());
                });

            await Task.Yield();
        }
    }

    private static long? SafeSize(
        Func<long> getter)
    {
        try
        {
            var result =
                getter();

            return result >= 0
                ? result
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