using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IArchiveFormatHandler
{
    DetectedFileType FileType { get; }

    bool RequiresSeekableInput { get; }

    IAsyncEnumerable<ArchiveFormatEntry> ReadEntriesAsync(
        Stream stream,
        string logicalName,
        CancellationToken cancellationToken = default);
}