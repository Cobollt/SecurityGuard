using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.Service.Application;

public sealed class SecurityRuleExpirationService
{
    private readonly IRuleRepository _ruleRepository;
    private readonly IRuleManagementService _ruleManagementService;
    private readonly IAuditService _auditService;

    public SecurityRuleExpirationService(
        IRuleRepository ruleRepository,
        IRuleManagementService ruleManagementService,
        IAuditService auditService)
    {
        _ruleRepository =
            ruleRepository;

        _ruleManagementService =
            ruleManagementService;

        _auditService =
            auditService;
    }

    public async Task<int> RemoveExpiredAsync(
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken = default)
    {
        var rules =
            await _ruleRepository.GetAllAsync(
                cancellationToken);

        var expired =
            rules
                .Where(
                    rule =>
                        rule.ExpiresAtUtc is not null &&
                        rule.ExpiresAtUtc <=
                        nowUtc)
                .OrderBy(
                    rule =>
                        rule.ExpiresAtUtc)
                .ToArray();

        var removed =
            0;

        foreach (var rule in expired)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                await _ruleManagementService.DeleteAsync(
                    rule.Id,
                    cancellationToken);

                removed++;
            }
            catch (Exception exception)
            {
                await _auditService.WriteAsync(
                    SecurityModuleKind.Core,
                    SecurityEventType.Rule,
                    SecuritySeverity.High,
                    "Expired security rule cleanup failed",
                    $"RuleId={rule.Id}; Name={rule.Name}; Error={exception.Message}",
                    cancellationToken:
                        cancellationToken);
            }
        }

        return removed;
    }
}