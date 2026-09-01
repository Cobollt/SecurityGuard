namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IKnownThreatHashStore
{
    Task<bool> IsMaliciousAsync(
        string sha256,
        CancellationToken cancellationToken = default);
}