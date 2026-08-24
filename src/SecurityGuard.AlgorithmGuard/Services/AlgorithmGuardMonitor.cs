using SecurityGuard.AlgorithmGuard.Contracts;

namespace SecurityGuard.AlgorithmGuard.Services;

public sealed class AlgorithmGuardMonitor
    : IAlgorithmGuardMonitor
{
    private readonly IProcessStartMonitor _processStartMonitor;
    private readonly IProcessMetadataProvider _metadataProvider;
    private readonly IProcessAncestryProvider _ancestryProvider;
    private readonly IAlgorithmExecutionAnalyzer _analyzer;
    private readonly AlgorithmPolicyService _policyService;
    private readonly IInternalProcessRegistry _internalProcessRegistry;
    private readonly InterpreterCatalog _interpreterCatalog;

    public AlgorithmGuardMonitor(
        IProcessStartMonitor processStartMonitor,
        IProcessMetadataProvider metadataProvider,
        IProcessAncestryProvider ancestryProvider,
        IAlgorithmExecutionAnalyzer analyzer,
        AlgorithmPolicyService policyService,
        IInternalProcessRegistry internalProcessRegistry,
        InterpreterCatalog interpreterCatalog)
    {
        _processStartMonitor =
            processStartMonitor;

        _metadataProvider =
            metadataProvider;

        _ancestryProvider =
            ancestryProvider;

        _analyzer =
            analyzer;

        _policyService =
            policyService;

        _internalProcessRegistry =
            internalProcessRegistry;

        _interpreterCatalog =
            interpreterCatalog;
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

                var ancestry =
                    await _ancestryProvider.GetAsync(
                        metadata,
                        cancellationToken);

                var correlationId =
                    AlgorithmExecutionChainId.Create(
                        metadata,
                        ancestry,
                        _interpreterCatalog);

                attempt =
                    attempt with
                    {
                        ExecutionChain =
                            ancestry,

                        CorrelationId =
                            correlationId
                    };

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