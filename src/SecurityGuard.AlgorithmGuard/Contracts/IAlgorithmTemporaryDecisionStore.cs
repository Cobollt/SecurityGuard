namespace SecurityGuard.AlgorithmGuard.Contracts;

public interface IAlgorithmTemporaryDecisionStore
{
    void AllowOnce(string identity);

    bool TryConsumeAllowOnce(string identity);
}