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

    public SecurityDecisionService(
        IDecisionRequestRepository requestRepository,
        IEnumerable<ISecurityDecisionHandler> handlers,
        IAuditService auditService)
    {
        _requestRepository = requestRepository;
        _auditService = auditService;

        _handlers =
            handlers.ToDictionary(
                handler => handler.Module);
    }

    public async Task ApplyAsync(
        SecurityDecision decision,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(decision);

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
            cancellationToken: cancellationToken);
    }
}