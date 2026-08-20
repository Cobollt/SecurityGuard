using SecurityGuard.AlgorithmGuard.Contracts;

namespace SecurityGuard.AlgorithmGuard.Services;

public sealed class AlgorithmGuardMonitor
    : IAlgorithmGuardMonitor
{
    private readonly IProcessStartMonitor _processStartMonitor;
    private readonly IProcessMetadataProvider _metadataProvider;
    private readonly IAlgorithmExecutionAnalyzer _analyzer;
    private readonly AlgorithmPolicyService _policyService;
    private readonly IInternalProcessRegistry _internalProcessRegistry;

    public AlgorithmGuardMonitor(
        IProcessStartMonitor processStartMonitor,
        IProcessMetadataProvider metadataProvider,
        IAlgorithmExecutionAnalyzer analyzer,
        AlgorithmPolicyService policyService,
        IInternalProcessRegistry internalProcessRegistry)
    {
        _processStartMonitor =
            processStartMonitor;

        _metadataProvider =
            metadataProvider;

        _analyzer =
            analyzer;

        _policyService =
            policyService;

        _internalProcessRegistry =
            internalProcessRegistry;
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
                if (_internalProcessRegistry.TryConsume(
                        signal.ProcessId))
                {
                    continue;
                }

                if (signal.ParentProcessId ==
                    Environment.ProcessId)
                {
                    continue;
                }

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

                await _policyService.HandleAsync(
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