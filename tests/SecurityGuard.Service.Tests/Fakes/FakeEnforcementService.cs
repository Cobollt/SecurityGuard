using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Enums;
using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.Service.Tests.Fakes;

public sealed class FakeEnforcementService : IAlgorithmEnforcementService
{
    public AlgorithmEnforcementLevel Level { get; set; } =
        AlgorithmEnforcementLevel.Unsupported;

    public AlgorithmEnforcementResult? Result { get; set; }

    public int GetLevelCallCount { get; private set; }

    public int AddBlockCallCount { get; private set; }

    public string? LastFilePath { get; private set; }

    public Guid? LastSecurityRuleId { get; private set; }

    public AlgorithmEnforcementLevel GetLevel(string? filePath)
    {
        GetLevelCallCount++;
        LastFilePath = filePath;

        return Level;
    }

    public Task<AlgorithmEnforcementResult> AddBlockAsync(
        Guid securityRuleId,
        string filePath,
        CancellationToken cancellationToken = default)
    {
        AddBlockCallCount++;
        LastSecurityRuleId = securityRuleId;
        LastFilePath = filePath;

        if (Result is null)
        {
            throw new InvalidOperationException(
                "FakeEnforcementService.Result was not configured.");
        }

        return Task.FromResult(Result);
    }
}