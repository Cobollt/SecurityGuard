using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.AlgorithmGuard.Contracts;

public interface IAuthenticodeSignatureService
{
    Task<AuthenticodeSignatureInfo> GetAsync(
        string filePath,
        CancellationToken cancellationToken = default);
}