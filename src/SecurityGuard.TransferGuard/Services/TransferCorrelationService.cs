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
    private readonly TransferCorrelationConfidenceCalculator _confidenceCalculator;
    private readonly TransferGuardOptions _options;
    private readonly TransferFilePolicyService _filePolicyService;

    private readonly ConcurrentDictionary<string, DateTimeOffset> _emitted =
        new(
            StringComparer.OrdinalIgnoreCase);

    public TransferCorrelationService(
        ITransferCorrelationState state,
        IFileHashService hashService,
        IAuditService auditService,
        TransferCorrelationConfidenceCalculator confidenceCalculator,
        TransferFilePolicyService filePolicyService,
        TransferGuardOptions options)
    {
        _state =
            state;

        _hashService =
            hashService;

        _auditService =
            auditService;

        _confidenceCalculator =
            confidenceCalculator;

        _filePolicyService =
            filePolicyService;

        _options =
            options;
    }

    public async Task HandleFileReadAsync(
        FileReadActivity activity,
        CancellationToken cancellationToken = default)
    {
        _state.RecordFileRead(
            activity);

        var sends =
            _state.GetRecentNetworkSends(
                activity.ProcessId,
                activity.ReadAtUtc);

        foreach (var send in sends)
        {
            var connection =
                FindConnection(
                    activity.ProcessId,
                    send,
                    activity.ReadAtUtc);

            if (connection is null)
            {
                continue;
            }

            var file =
                _state.GetRecentFiles(
                        activity.ProcessId,
                        activity.ReadAtUtc)
                    .FirstOrDefault(
                        item =>
                            string.Equals(
                                item.FilePath,
                                activity.FilePath,
                                StringComparison.OrdinalIgnoreCase));

            if (file is null)
            {
                continue;
            }

            await EmitCandidateAsync(
                file,
                send,
                connection,
                cancellationToken);
        }
    }

    public async Task HandleNetworkSendAsync(
        NetworkSendActivity activity,
        CancellationToken cancellationToken = default)
    {
        _state.RecordNetworkSend(
            activity);

        var connection =
            FindConnection(
                activity.ProcessId,
                activity,
                activity.SentAtUtc);

        if (connection is null)
        {
            return;
        }

        var send =
            _state.GetRecentNetworkSends(
                    activity.ProcessId,
                    activity.SentAtUtc)
                .FirstOrDefault(
                    item =>
                        Matches(
                            item,
                            activity));

        if (send is null)
        {
            return;
        }

        var files =
            _state.GetRecentFiles(
                activity.ProcessId,
                activity.SentAtUtc);

        foreach (var file in files)
        {
            await EmitCandidateAsync(
                file,
                send,
                connection,
                cancellationToken);
        }
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

        var sends =
            _state.GetRecentNetworkSends(
                    processId.Value,
                    observation.DetectedAtUtc)
                .Where(
                    send =>
                        Matches(
                            send,
                            observation))
                .ToArray();

        if (sends.Length == 0)
        {
            return;
        }

        var files =
            _state.GetRecentFiles(
                processId.Value,
                observation.DetectedAtUtc);

        foreach (var send in sends)
        {
            foreach (var file in files)
            {
                await EmitCandidateAsync(
                    file,
                    send,
                    observation,
                    cancellationToken);
            }
        }
    }

    private NetworkConnectionObservation? FindConnection(
        int processId,
        RecentNetworkSend send,
        DateTimeOffset referenceTime)
    {
        return _state.GetRecentConnections(
                processId,
                referenceTime)
            .FirstOrDefault(
                connection =>
                    Matches(
                        send,
                        connection));
    }

    private NetworkConnectionObservation? FindConnection(
        int processId,
        NetworkSendActivity send,
        DateTimeOffset referenceTime)
    {
        return _state.GetRecentConnections(
                processId,
                referenceTime)
            .FirstOrDefault(
                connection =>
                    Matches(
                        send,
                        connection));
    }

    private async Task EmitCandidateAsync(
        RecentFileRead file,
        RecentNetworkSend send,
        NetworkConnectionObservation connection,
        CancellationToken cancellationToken)
    {
        var identity =
            BuildIdentity(
                file,
                send);

        CleanupEmitted();

        if (!_emitted.TryAdd(
                identity,
                DateTimeOffset.UtcNow))
        {
            return;
        }

        long? fileSize =
            null;

        try
        {
            if (File.Exists(
                    file.FilePath))
            {
                fileSize =
                    new FileInfo(
                        file.FilePath)
                    .Length;
            }
        }
        catch
        {
        }

        var assessment =
            _confidenceCalculator.Calculate(
                file,
                send,
                fileSize);

        string? sha256 =
            null;

        if (assessment.Confidence !=
                TransferCorrelationConfidence.Low &&
            fileSize is > 0 &&
            fileSize <=
            _options.MaxImmediateHashFileSizeBytes)
        {
            try
            {
                sha256 =
                    await _hashService.ComputeSha256Async(
                        file.FilePath,
                        cancellationToken);
            }
            catch
            {
            }
        }

        var difference =
            (file.LastReadAtUtc -
             send.LastSendAtUtc)
            .Duration();

        var classification =
            file.Classification ??
            TransferFileClassification.Default;

        var candidate =
            new FileTransferCandidate(
                Guid.NewGuid(),
                DateTimeOffset.UtcNow,
                file.ProcessId,
                file.FilePath,
                sha256,
                file.ObservedReadBytes,
                send.ObservedSentBytes,
                fileSize,
                difference,
                assessment.VolumeSimilarity,
                assessment.Confidence,
                classification,
                connection);

        await _auditService.WriteAsync(
            SecurityModuleKind.TransferGuard,
            SecurityEventType.FileTransfer,
            GetSeverity(
                assessment.Confidence),
            "Possible file transfer correlation",
            BuildDetails(
                candidate),
            SecurityAction.None,
            cancellationToken:
                cancellationToken);
        
        await _filePolicyService.HandleAsync(
            candidate,
            cancellationToken);
    }

    private static bool Matches(
        RecentNetworkSend send,
        NetworkConnectionObservation connection)
    {
        return send.Protocol ==
                   connection.Protocol &&
               send.RemotePort ==
                   connection.RemotePort &&
               string.Equals(
                   send.RemoteAddress,
                   connection.RemoteAddress,
                   StringComparison.OrdinalIgnoreCase) &&
               PortsCompatible(
                   send.LocalPort,
                   connection.LocalPort);
    }

    private static bool Matches(
        NetworkSendActivity send,
        NetworkConnectionObservation connection)
    {
        return send.Protocol ==
                   connection.Protocol &&
               send.RemotePort ==
                   connection.RemotePort &&
               string.Equals(
                   send.RemoteAddress,
                   connection.RemoteAddress,
                   StringComparison.OrdinalIgnoreCase) &&
               PortsCompatible(
                   send.LocalPort,
                   connection.LocalPort);
    }

    private static bool Matches(
        RecentNetworkSend recent,
        NetworkSendActivity activity)
    {
        return recent.Protocol ==
                   activity.Protocol &&
               recent.LocalPort ==
                   activity.LocalPort &&
               recent.RemotePort ==
                   activity.RemotePort &&
               string.Equals(
                   recent.RemoteAddress,
                   activity.RemoteAddress,
                   StringComparison.OrdinalIgnoreCase);
    }

    private static bool PortsCompatible(
        int first,
        int second)
    {
        return first <= 0 ||
               second <= 0 ||
               first == second;
    }

    private static SecuritySeverity GetSeverity(
        TransferCorrelationConfidence confidence)
    {
        return confidence switch
        {
            TransferCorrelationConfidence.High =>
                SecuritySeverity.High,

            TransferCorrelationConfidence.Medium =>
                SecuritySeverity.Medium,

            _ =>
                SecuritySeverity.Info
        };
    }

    private static string BuildIdentity(
        RecentFileRead file,
        RecentNetworkSend send)
    {
        return string.Join(
            "|",
            file.ProcessId,
            file.FilePath,
            send.Protocol,
            send.RemoteAddress,
            send.RemotePort);
    }

    private static string BuildDetails(
        FileTransferCandidate candidate)
    {
        return string.Join(
            Environment.NewLine,
            new[]
            {
                "Correlation only: file content transmission is not cryptographically proven.",
                $"Confidence: {candidate.Confidence}",
                $"PID: {candidate.ProcessId}",
                $"Process: {candidate.Connection.Process?.ProcessName ?? "Unknown"}",
                $"Executable: {candidate.Connection.Process?.ExecutablePath ?? "Unknown"}",
                $"File: {candidate.FilePath}",
                $"File category: {candidate.Classification.Category}",
                $"File priority: {candidate.Classification.Priority}",
                $"Classification: {candidate.Classification.Reason}",
                $"SHA256: {candidate.Sha256 ?? "Not calculated"}",
                $"File size: {candidate.FileSize?.ToString() ?? "Unknown"}",
                $"Observed read bytes: {candidate.ObservedReadBytes}",
                $"Observed sent bytes: {candidate.ObservedSentBytes}",
                $"Volume similarity: {candidate.VolumeSimilarity:P1}",
                $"Time difference: {candidate.TimeDifference.TotalMilliseconds:F0} ms",
                $"Protocol: {candidate.Connection.Protocol}",
                $"Remote: {candidate.Connection.RemoteAddress}:{candidate.Connection.RemotePort}"
            });
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