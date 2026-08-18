using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.AlgorithmGuard.Services;

public static class AlgorithmExecutionIdentity
{
    private async Task<string> CreateIdentityAsync(
    SecurityDecisionRequest request,
    CancellationToken cancellationToken)
{
    if (!string.IsNullOrWhiteSpace(
            request.FilePath) &&
        File.Exists(
            request.FilePath))
    {
        var hash =
            await _hashService.ComputeSha256Async(
                request.FilePath,
                cancellationToken);

        return $"HASH:{hash}";
    }

    if (!string.IsNullOrWhiteSpace(
            request.Description))
    {
        return string.Join(
            ":",
            "COMMAND",
            request.ProcessName ?? string.Empty,
            request.Description);
    }

    throw new InvalidOperationException(
        "Unable to determine execution identity.");
}
}