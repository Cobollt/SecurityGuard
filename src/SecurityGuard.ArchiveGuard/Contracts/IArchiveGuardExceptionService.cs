namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IArchiveGuardExceptionService
{
    Task AddSha256ExceptionAsync(
        string sha256,
        string fileName,
        CancellationToken cancellationToken = default);

    // Keep the exception in place during the operation; remove only a newly
    // created exception if the operation fails.
    Task<T> ExecuteWithSha256ExceptionAsync<T>(
        string sha256,
        string fileName,
        Func<CancellationToken, Task<T>> operation,
        CancellationToken cancellationToken = default);
}
