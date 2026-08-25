namespace SecurityGuard.TransferGuard.Configuration;

public sealed class TransferGuardOptions
{
    public TimeSpan PollInterval { get; init; } =
        TimeSpan.FromMilliseconds(500);

    public bool IgnoreLoopback { get; init; } =
        true;

    public bool AutoEnableFilteringPlatformAudit { get; init; } =
        true;

    public TimeSpan PendingDecisionLifetime { get; init; } =
        TimeSpan.FromMinutes(10);
}