using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferTelemetryHealthTracker
    : ITransferTelemetryHealthTracker
{
    private long _kernelDrops;
    private long _wfpDrops;
    private long _kernelFailures;
    private long _wfpSubscriptionFailures;
    private long _wfpParseFailures;
    private long _correlationFailures;
    private long _lastProblemTicks;

    public void RecordKernelDrop()
    {
        Interlocked.Increment(
            ref _kernelDrops);

        RecordProblemTime();
    }

    public void RecordWfpDrop()
    {
        Interlocked.Increment(
            ref _wfpDrops);

        RecordProblemTime();
    }

    public void RecordKernelSourceFailure()
    {
        Interlocked.Increment(
            ref _kernelFailures);

        RecordProblemTime();
    }

    public void RecordWfpSubscriptionFailure()
    {
        Interlocked.Increment(
            ref _wfpSubscriptionFailures);

        RecordProblemTime();
    }

    public void RecordWfpParseFailure()
    {
        Interlocked.Increment(
            ref _wfpParseFailures);

        RecordProblemTime();
    }

    public void RecordCorrelationFailure()
    {
        Interlocked.Increment(
            ref _correlationFailures);

        RecordProblemTime();
    }

    public TransferTelemetryHealthSnapshot GetSnapshot()
    {
        var ticks =
            Interlocked.Read(
                ref _lastProblemTicks);

        return new TransferTelemetryHealthSnapshot(
            Interlocked.Read(
                ref _kernelDrops),
            Interlocked.Read(
                ref _wfpDrops),
            Interlocked.Read(
                ref _kernelFailures),
            Interlocked.Read(
                ref _wfpSubscriptionFailures),
            Interlocked.Read(
                ref _wfpParseFailures),
            Interlocked.Read(
                ref _correlationFailures),
            ticks == 0
                ? null
                : new DateTimeOffset(
                    ticks,
                    TimeSpan.Zero));
    }

    private void RecordProblemTime()
    {
        Interlocked.Exchange(
            ref _lastProblemTicks,
            DateTimeOffset.UtcNow.UtcTicks);
    }
}