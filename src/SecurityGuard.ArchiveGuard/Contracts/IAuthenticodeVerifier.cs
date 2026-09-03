using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IAuthenticodeVerifier
{
    Task<AuthenticodeAnalysisResult> VerifyAsync(
        string filePath,
        CancellationToken cancellationToken = default);
}