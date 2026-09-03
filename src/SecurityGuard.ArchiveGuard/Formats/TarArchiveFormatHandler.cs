using System.Formats.Tar;
using System.Runtime.CompilerServices;
using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Formats;

public sealed class TarArchiveFormatHandler
    : IArchiveFormatHandler
{
    public DetectedFileType FileType =>
        DetectedFileType.Tar;

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

        await using var reader =
            new TarReader(
                stream,
                leaveOpen:
                    true);

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var entry =
                await reader.GetNextEntryAsync(
                    copyData:
                        false,
                    cancellationToken);

            if (entry is null)
            {
                yield break;
            }

            var directory =
                entry.EntryType ==
                    TarEntryType.Directory ||
                entry.EntryType ==
                    TarEntryType.DirectoryList;

            var link =
                entry.EntryType ==
                    TarEntryType.SymbolicLink ||
                entry.EntryType ==
                    TarEntryType.HardLink ||
                entry.EntryType ==
                    TarEntryType.RenamedOrSymlinked;

            var linkTarget =
                GetLinkTarget(
                    entry);

            var capturedStream =
                entry.DataStream;

            yield return new ArchiveFormatEntry(
                entry.Name,
                entry.Length,
                null,
                directory,
                false,
                link,
                linkTarget,
                entry.ModificationTime.ToUniversalTime(),
                token =>
                {
                    token.ThrowIfCancellationRequested();

                    return ValueTask.FromResult(
                        capturedStream ??
                        Stream.Null);
                });
        }
    }

    private static string? GetLinkTarget(
        TarEntry entry)
    {
        if (entry.EntryType !=
                TarEntryType.SymbolicLink &&
            entry.EntryType !=
                TarEntryType.HardLink)
        {
            return null;
        }

        return entry.LinkName;
    }
}