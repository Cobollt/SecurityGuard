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

    public TimeSpan FileCorrelationWindow { get; init; } =
        TimeSpan.FromSeconds(15);

    public int MaxTrackedFilesPerProcess { get; init; } =
        64;

    public int MaxTrackedConnectionsPerProcess { get; init; } =
        32;

    public int MaxTrackedNetworkDestinationsPerProcess { get; init; } =
        64;

    public int MaxCandidatesPerConnection { get; init; } =
        5;

    public int KernelTelemetryChannelCapacity { get; init; } =
        16384;

    public long MaxImmediateHashFileSizeBytes { get; init; } =
        32L * 1024L * 1024L;

    public TimeSpan CandidateDeduplicationLifetime { get; init; } =
        TimeSpan.FromSeconds(30);

    public TimeSpan FileBlockEnforcementLifetime { get; init; } =
        TimeSpan.FromMinutes(2);

    public TimeSpan TemporaryEnforcementCleanupInterval { get; init; } =
        TimeSpan.FromSeconds(15);
}