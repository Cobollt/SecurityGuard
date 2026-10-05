using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.Service.Application;

public sealed class SecurityDecisionService
    : ISecurityDecisionService
{
    private readonly IDecisionRequestRepository _requestRepository;

    private readonly IReadOnlyDictionary<
        SecurityModuleKind,
        ISecurityDecisionHandler> _handlers;

    private readonly IAuditService _auditService;

    private readonly SemaphoreSlim _applyGate =
    new(
        1,
        1);

    public SecurityDecisionService(
        IDecisionRequestRepository requestRepository,
        IEnumerable<ISecurityDecisionHandler> handlers,
        IAuditService auditService)
    {
        _requestRepository =
            requestRepository;

        _auditService =
            auditService;

        _handlers =
            handlers.ToDictionary(
                handler =>
                    handler.Module);
    }

    public async Task ApplyAsync(
        SecurityDecision decision,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            decision);

        await _applyGate.WaitAsync(
            cancellationToken);

        try
        {
            var request =
                await _requestRepository.GetByIdAsync(
                    decision.RequestId,
                    cancellationToken);

            if (request is null)
            {
                throw new InvalidOperationException(
                    $"Decision request '{decision.RequestId}' was not found.");
            }

            if (!request.AvailableActions.Contains(
                    decision.Action))
            {
                throw new InvalidOperationException(
                    $"Action '{decision.Action}' is not allowed for this request.");
            }

            if (!_handlers.TryGetValue(
                    request.Module,
                    out var handler))
            {
                throw new InvalidOperationException(
                    $"No decision handler is registered for module '{request.Module}'.");
            }

            await handler.HandleAsync(
                request,
                decision,
                cancellationToken);

            if (decision.Action ==
                    SecurityAction.AllowApplication ||
                decision.Action ==
                    SecurityAction.BlockApplication)
            {
                await RemoveApplicationPendingRequestsAsync(
                    request,
                    cancellationToken);
            }

            await _requestRepository.RemoveAsync(
                request.Id,
                cancellationToken);

            await _auditService.WriteAsync(
                request.Module,
                SecurityEventType.Audit,
                SecuritySeverity.Info,
                "Security decision applied",
                $"{request.Title}: {decision.Action}",
                decision.Action,
                cancellationToken:
                    cancellationToken);
        }
        finally
        {
            _applyGate.Release();
        }
    }

    private async Task RemoveApplicationPendingRequestsAsync(
        SecurityDecisionRequest resolvedRequest,
        CancellationToken cancellationToken)
    {
        var processPath =
            resolvedRequest.RuleContext?.ProcessPath;

        if (string.IsNullOrWhiteSpace(
                processPath))
        {
            return;
        }

        var pending =
            await _requestRepository.GetPendingAsync(
                cancellationToken);

        var staleRequestIds =
            pending
                .Where(
                    request =>
                        request.Id !=
                        resolvedRequest.Id)
                .Where(
                    request =>
                        request.Module ==
                        resolvedRequest.Module)
                .Where(
                    request =>
                        string.Equals(
                            request.RuleContext?.ProcessPath,
                            processPath,
                            StringComparison.OrdinalIgnoreCase))
                .Select(
                    request =>
                        request.Id)
                .ToArray();

        foreach (var requestId in
                 staleRequestIds)
        {
            await _requestRepository.RemoveAsync(
                requestId,
                cancellationToken);
        }
    }
}