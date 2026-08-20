using SecurityGuard.AlgorithmGuard.Enums;
using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.AlgorithmGuard.Contracts;

public interface IAlgorithmEnforcementService
{
    AlgorithmEnforcementLevel GetLevel(
        string? filePath);

    Task<AlgorithmEnforcementResult> AddBlockAsync(
        Guid securityRuleId,
        string filePath,
        CancellationToken cancellationToken = default);

    Task RemoveBlockAsync(
        Guid securityRuleId,
        CancellationToken cancellationToken = default);

    Task<AlgorithmEnforcementSnapshot> InspectAsync(
        CancellationToken cancellationToken = default);
}