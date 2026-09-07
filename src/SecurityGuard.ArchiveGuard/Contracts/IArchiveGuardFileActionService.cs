namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IArchiveGuardFileActionService
{
    Task KeepAsync(
        string filePath,
        CancellationToken cancellationToken = default);

    Task QuarantineAsync(
        string filePath,
        string reason,
        CancellationToken cancellationToken = default);

    Task DeleteAsync(
        string filePath,
        CancellationToken cancellationToken = default);
}