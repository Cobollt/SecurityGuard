using Microsoft.Extensions.Hosting;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Service.Application;

namespace SecurityGuard.Service.Hosting;

public sealed class SecurityRuleExpirationHostedService
    : BackgroundService
{
    private static readonly TimeSpan Interval =
        TimeSpan.FromSeconds(15);

    private readonly SecurityRuleExpirationService _expirationService;
    private readonly IAuditService _auditService;

    public SecurityRuleExpirationHostedService(
        SecurityRuleExpirationService expirationService,
        IAuditService auditService)
    {
        _expirationService =
            expirationService;

        _auditService =
            auditService;
    }

    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        await CleanupAsync(
            stoppingToken);

        using var timer =
            new PeriodicTimer(
                Interval);

        while (await timer.WaitForNextTickAsync(
                   stoppingToken))
        {
            await CleanupAsync(
                stoppingToken);
        }
    }

    private async Task CleanupAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            var removed =
                await _expirationService.RemoveExpiredAsync(
                    DateTimeOffset.UtcNow,
                    cancellationToken);

            if (removed <= 0)
            {
                return;
            }

            await _auditService.WriteAsync(
                SecurityModuleKind.Core,
                SecurityEventType.Rule,
                SecuritySeverity.Info,
                "Expired security rules removed",
                $"Removed rules: {removed}",
                cancellationToken:
                    cancellationToken);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            try
            {
                await _auditService.WriteAsync(
                    SecurityModuleKind.Core,
                    SecurityEventType.Rule,
                    SecuritySeverity.High,
                    "Security rule expiration maintenance failed",
                    exception.Message,
                    cancellationToken:
                        CancellationToken.None);
            }
            catch
            {
            }
        }
    }
}