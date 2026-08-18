using SecurityGuard.AlgorithmGuard.Contracts;

namespace SecurityGuard.AlgorithmGuard.Services;

public sealed class AlgorithmGuardMonitor
    : IAlgorithmGuardMonitor
{
    private readonly IProcessStartMonitor _processStartMonitor;
    private readonly IProcessMetadataProvider _metadataProvider;
    private readonly IAlgorithmExecutionAnalyzer _analyzer;
    private readonly AlgorithmObservationService _observationService;

    public AlgorithmGuardMonitor(
        IProcessStartMonitor processStartMonitor,
        IProcessMetadataProvider metadataProvider,
        IAlgorithmExecutionAnalyzer analyzer,
        AlgorithmObservationService observationService)
    {
        _processStartMonitor =
            processStartMonitor;

        _metadataProvider =
            metadataProvider;

        _analyzer =
            analyzer;

        _observationService =
            observationService;
    }

    public async Task RunAsync(
        CancellationToken cancellationToken = default)
    {
        await foreach (
            var signal in
            _processStartMonitor.WatchAsync(
                cancellationToken))
        {
            try
            {
                var metadata =
                    await _metadataProvider.GetAsync(
                        signal.ProcessId,
                        cancellationToken);

                if (metadata is null)
                {
                    continue;
                }

                var attempt =
                    _analyzer.Analyze(
                        signal,
                        metadata);

                if (attempt is null)
                {
                    continue;
                }

                await _observationService.HandleAsync(
                    attempt,
                    cancellationToken);
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch
            {
            }
        }
    }
}