namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IArchiveGuardSpoolCleanupService
{
    Task<int> CleanupAsync(
        DateTimeOffset olderThanUtc,
        CancellationToken cancellationToken = default);
}