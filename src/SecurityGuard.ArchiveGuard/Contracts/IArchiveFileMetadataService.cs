using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IArchiveFileMetadataService
{
    Task<ArchiveFileMetadata> LoadAsync(
        string filePath,
        CancellationToken cancellationToken = default);
}