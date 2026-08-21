namespace SecurityGuard.AlgorithmGuard.Configuration;

public sealed class AlgorithmGuardOptions
{
    public TimeSpan PendingDecisionLifetime { get; init; } =
        TimeSpan.FromMinutes(10);

    public TimeSpan AllowOnceLifetime { get; init; } =
        TimeSpan.FromMinutes(5);

    public TimeSpan MaintenanceInterval { get; init; } =
        TimeSpan.FromMinutes(1);
}