namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IArchiveGuardExceptionService
{
    Task AddSha256ExceptionAsync(
        string sha256,
        string fileName,
        CancellationToken cancellationToken = default);
}