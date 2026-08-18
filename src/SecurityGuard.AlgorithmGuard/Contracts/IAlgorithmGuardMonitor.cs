namespace SecurityGuard.AlgorithmGuard.Contracts;

public interface IAlgorithmGuardMonitor
{
    Task RunAsync(
        CancellationToken cancellationToken = default);
}