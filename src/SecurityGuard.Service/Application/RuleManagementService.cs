using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.Service.Application;

public sealed class RuleManagementService
    : IRuleManagementService
{
    private readonly IRuleRepository _ruleRepository;
    private readonly IReadOnlyDictionary<
        SecurityModuleKind,
        ISecurityRuleLifecycleHandler> _handlers;

    private readonly IAuditService _auditService;

    public RuleManagementService(
        IRuleRepository ruleRepository,
        IEnumerable<ISecurityRuleLifecycleHandler> handlers,
        IAuditService auditService)
    {
        _ruleRepository =
            ruleRepository;

        _auditService =
            auditService;

        _handlers =
            handlers.ToDictionary(
                handler =>
                    handler.Module);
    }

    public Task<IReadOnlyList<SecurityRule>> GetAllAsync(
        CancellationToken cancellationToken = default)
    {
        return _ruleRepository.GetAllAsync(
            cancellationToken);
    }

    public async Task DeleteAsync(
        Guid ruleId,
        CancellationToken cancellationToken = default)
    {
        var rule =
            await _ruleRepository.GetByIdAsync(
                ruleId,
                cancellationToken);

        if (rule is null)
        {
            return;
        }

        if (_handlers.TryGetValue(
                rule.Module,
                out var handler))
        {
            await handler.BeforeDeleteAsync(
                rule,
                cancellationToken);
        }

        await _ruleRepository.DeleteAsync(
            rule.Id,
            cancellationToken);

        await _auditService.WriteAsync(
            rule.Module,
            SecurityEventType.Rule,
            SecuritySeverity.Info,
            "Security rule deleted",
            $"{rule.Name} ({rule.Id})",
            cancellationToken: cancellationToken);
    }
}