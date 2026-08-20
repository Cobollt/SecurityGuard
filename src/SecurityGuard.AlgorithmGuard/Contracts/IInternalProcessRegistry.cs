namespace SecurityGuard.AlgorithmGuard.Contracts;

public interface IInternalProcessRegistry
{
    void Register(int processId);

    bool TryConsume(int processId);
}