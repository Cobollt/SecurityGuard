using System.Collections.Concurrent;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.TransferGuard.Configuration;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferCorrelationService
{
    private readonly ITransferCorrelationState _state;
    private readonly IFileHashService _hashService;
    private readonly IAuditService _auditService;
    private readonly TransferGuardOptions _options;

    private readonly ConcurrentDictionary<string, DateTimeOffset> _emitted =
        new(
            StringComparer.OrdinalIgnoreCase);

    public TransferCorrelationService(
        ITransferCorrelationState state,
        IFileHashService hashService,
        IAuditService auditService,
        TransferGuardOptions options)
    {
        _state =
            state;

        _hashService =
            hashService;

        _auditService =
            auditService;

        _options =
            options;
    }

    public async Task HandleFileReadAsync(
        FileReadActivity activity,
        CancellationToken cancellationToken = default)
    {
        _state.RecordFileRead(
            activity);

        var connections =
            _state.GetRecentConnections(
                activity.ProcessId,
                activity.ReadAtUtc);

        if (connections.Count == 0)
        {
            return;
        }

        var files =
            _state.GetRecentFiles(
                activity.ProcessId,
                activity.ReadAtUtc);

        var file =
            files.FirstOrDefault(
                item =>
                    string.Equals(
                        item.FilePath,
                        activity.FilePath,
                        StringComparison.OrdinalIgnoreCase));

        if (file is null)
        {
            return;
        }

        var connection =
            connections[0];

        await EmitCandidateAsync(
            file,
            connection,
            cancellationToken);
    }

    public async Task HandleConnectionAsync(
        NetworkConnectionObservation observation,
        CancellationToken cancellationToken = default)
    {
        _state.RecordConnection(
            observation);

        var processId =
            observation.Process?.ProcessId;

        if (processId is null ||
            processId <= 0)
        {
            return;
        }

        var files =
            _state.GetRecentFiles(
                processId.Value,
                observation.DetectedAtUtc);

        foreach (var file in files)
        {
            await EmitCandidateAsync(
                file,
                observation,
                cancellationToken);
        }
    }

    private async Task EmitCandidateAsync(
        RecentFileRead file,
        NetworkConnectionObservation connection,
        CancellationToken cancellationToken)
    {
        var identity =
            BuildIdentity(
                file,
                connection);

        CleanupEmitted();

        if (!_emitted.TryAdd(
                identity,
                DateTimeOffset.UtcNow))
        {
            return;
        }

        long? fileSize =
            null;

        string? sha256 =
            null;

        try
        {
            if (File.Exists(
                    file.FilePath))
            {
                var info =
                    new FileInfo(
                        file.FilePath);

                fileSize =
                    info.Length;

                if (info.Length <=
                    _options.MaxImmediateHashFileSizeBytes)
                {
                    sha256 =
                        await _hashService.ComputeSha256Async(
                            info.FullName,
                            cancellationToken);
                }
            }
        }
        catch
        {
        }

        var difference =
            (file.LastReadAtUtc -
             connection.DetectedAtUtc)
            .Duration();

        var confidence =
            CalculateConfidence(
                difference,
                file.ObservedReadBytes,
                fileSize);

        var candidate =
            new FileTransferCandidate(
                Guid.NewGuid(),
                DateTimeOffset.UtcNow,
                file.ProcessId,
                file.FilePath,
                sha256,
                file.ObservedReadBytes,
                fileSize,
                difference,
                confidence,
                connection);

        await _auditService.WriteAsync(
            SecurityModuleKind.TransferGuard,
            SecurityEventType.FileTransfer,
            GetSeverity(
                confidence),
            "Possible file transfer correlation",
            BuildDetails(
                candidate),
            SecurityAction.None,
            cancellationToken:
                cancellationToken);
    }

    private static TransferCorrelationConfidence CalculateConfidence(
        TimeSpan difference,
        long observedReadBytes,
        long? fileSize)
    {
        var score =
            0;

        if (difference <=
            TimeSpan.FromSeconds(1))
        {
            score +=
                3;
        }
        else if (difference <=
                 TimeSpan.FromSeconds(3))
        {
            score +=
                2;
        }
        else
        {
            score +=
                1;
        }

        if (observedReadBytes >=
            64L * 1024L)
        {
            score +=
                2;
        }
        else if (observedReadBytes >=
                 4L * 1024L)
        {
            score +=
                1;
        }

        if (fileSize is > 0)
        {
            var ratio =
                Math.Min(
                    1.0,
                    (double)observedReadBytes /
                    fileSize.Value);

            if (ratio >=
                0.8)
            {
                score +=
                    2;
            }
            else if (ratio >=
                     0.25)
            {
                score +=
                    1;
            }
        }

        if (score >= 6)
        {
            return TransferCorrelationConfidence.High;
        }

        if (score >= 4)
        {
            return TransferCorrelationConfidence.Medium;
        }

        return TransferCorrelationConfidence.Low;
    }

    private static SecuritySeverity GetSeverity(
        TransferCorrelationConfidence confidence)
    {
        return confidence switch
        {
            TransferCorrelationConfidence.High =>
                SecuritySeverity.Medium,

            TransferCorrelationConfidence.Medium =>
                SecuritySeverity.Low,

            _ =>
                SecuritySeverity.Info
        };
    }

    private static string BuildDetails(
        FileTransferCandidate candidate)
    {
        return string.Join(
            Environment.NewLine,
            new[]
            {
                "Correlation only: this does not prove that the file contents were transmitted.",
                $"Confidence: {candidate.Confidence}",
                $"PID: {candidate.ProcessId}",
                $"Process: {candidate.Connection.Process?.ProcessName ?? "Unknown"}",
                $"Executable: {candidate.Connection.Process?.ExecutablePath ?? "Unknown"}",
                $"File: {candidate.FilePath}",
                $"SHA256: {candidate.Sha256 ?? "Not calculated"}",
                $"Observed read bytes: {candidate.ObservedReadBytes}",
                $"File size: {candidate.FileSize?.ToString() ?? "Unknown"}",
                $"Time difference: {candidate.TimeDifference.TotalMilliseconds:F0} ms",
                $"Protocol: {candidate.Connection.Protocol}",
                $"Remote: {candidate.Connection.RemoteAddress}:{candidate.Connection.RemotePort}"
            });
    }

    private static string BuildIdentity(
        RecentFileRead file,
        NetworkConnectionObservation connection)
    {
        return string.Join(
            "|",
            file.ProcessId,
            file.FilePath,
            connection.Protocol,
            connection.RemoteAddress,
            connection.RemotePort);
    }

    private void CleanupEmitted()
    {
        var cutoff =
            DateTimeOffset.UtcNow -
            _options.CandidateDeduplicationLifetime;

        foreach (var item in _emitted)
        {
            if (item.Value >=
                cutoff)
            {
                continue;
            }

            _emitted.TryRemove(
                item.Key,
                out _);
        }
    }
}