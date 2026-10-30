using SecurityGuard.Core.Models;

namespace SecurityGuard.Core.Contracts;

public interface IWindowsSystemProcessTrustService
{
    Task<WindowsSystemProcessTrustResult> EvaluateAsync(
        WindowsSystemProcessTrustRequest request,
        CancellationToken cancellationToken = default);
}