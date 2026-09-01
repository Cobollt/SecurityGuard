using SecurityGuard.TransferGuard.Services;

namespace SecurityGuard.TransferGuard.Tests;

public sealed class TransferTelemetryHealthTrackerTests
{
    [Fact]
    public void Telemetry_failures_are_counted()
    {
        var tracker =
            new TransferTelemetryHealthTracker();

        tracker.RecordKernelDrop();
        tracker.RecordKernelDrop();
        tracker.RecordWfpDrop();
        tracker.RecordWfpSubscriptionFailure();
        tracker.RecordCorrelationFailure();

        var result =
            tracker.GetSnapshot();

        Assert.Equal(
            2,
            result.KernelActivitiesDropped);

        Assert.Equal(
            1,
            result.WfpEventsDropped);

        Assert.Equal(
            1,
            result.WfpSubscriptionFailures);

        Assert.Equal(
            1,
            result.CorrelationFailures);

        Assert.NotNull(
            result.LastProblemAtUtc);
    }
}