using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.AlgorithmGuard.Contracts;

public interface IAlgorithmExecutionAnalyzer
{
    AlgorithmExecutionAttempt? Analyze(
        ProcessStartSignal signal,
        ProcessMetadata metadata);
}