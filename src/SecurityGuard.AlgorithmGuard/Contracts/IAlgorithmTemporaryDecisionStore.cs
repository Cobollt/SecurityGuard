namespace SecurityGuard.AlgorithmGuard.Contracts;

public interface IAlgorithmTemporaryDecisionStore
{
    void AllowOnce(
        string identity,
        DateTimeOffset expiresAtUtc);

    bool TryConsumeAllowOnce(
        string identity);
}