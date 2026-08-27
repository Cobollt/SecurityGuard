using System.Collections.Concurrent;
using SecurityGuard.TransferGuard.Configuration;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferCorrelationState
    : ITransferCorrelationState
{
    private readonly ConcurrentDictionary<int, ProcessState> _states =
        new();

    private readonly TransferGuardOptions _options;

    public TransferCorrelationState(
        TransferGuardOptions options)
    {
        _options =
            options;
    }

    public void RecordFileRead(
        FileReadActivity activity)
    {
        ArgumentNullException.ThrowIfNull(
            activity);

        if (activity.ProcessId <= 0 ||
            string.IsNullOrWhiteSpace(
                activity.FilePath))
        {
            return;
        }

        var state =
            _states.GetOrAdd(
                activity.ProcessId,
                _ =>
                    new ProcessState());

        lock (state.Gate)
        {
            Cleanup(
                state,
                activity.ReadAtUtc);

            if (state.Files.TryGetValue(
                    activity.FilePath,
                    out var existing))
            {
                state.Files[activity.FilePath] =
                    existing with
                    {
                        ObservedReadBytes =
                            existing.ObservedReadBytes +
                            activity.BytesRead,

                        LastReadAtUtc =
                            activity.ReadAtUtc
                    };
            }
            else
            {
                state.Files[activity.FilePath] =
                    new RecentFileRead(
                        activity.ProcessId,
                        activity.FilePath,
                        activity.BytesRead,
                        activity.ReadAtUtc,
                        activity.ReadAtUtc);
            }

            TrimFiles(
                state);
        }
    }

    public void RecordConnection(
        NetworkConnectionObservation observation)
    {
        ArgumentNullException.ThrowIfNull(
            observation);

        var processId =
            observation.Process?.ProcessId;

        if (processId is null ||
            processId <= 0)
        {
            return;
        }

        var state =
            _states.GetOrAdd(
                processId.Value,
                _ =>
                    new ProcessState());

        lock (state.Gate)
        {
            Cleanup(
                state,
                observation.DetectedAtUtc);

            state.Connections.Add(
                observation);

            if (state.Connections.Count >
                _options.MaxTrackedConnectionsPerProcess)
            {
                state.Connections.RemoveRange(
                    0,
                    state.Connections.Count -
                    _options.MaxTrackedConnectionsPerProcess);
            }
        }
    }

    public IReadOnlyList<RecentFileRead> GetRecentFiles(
        int processId,
        DateTimeOffset referenceTime)
    {
        if (!_states.TryGetValue(
                processId,
                out var state))
        {
            return [];
        }

        lock (state.Gate)
        {
            Cleanup(
                state,
                referenceTime);

            return state.Files.Values
                .Where(
                    file =>
                        IsWithinWindow(
                            file.LastReadAtUtc,
                            referenceTime))
                .OrderByDescending(
                    file =>
                        file.LastReadAtUtc)
                .ThenByDescending(
                    file =>
                        file.ObservedReadBytes)
                .Take(
                    _options.MaxCandidatesPerConnection)
                .ToArray();
        }
    }

    public IReadOnlyList<NetworkConnectionObservation> GetRecentConnections(
        int processId,
        DateTimeOffset referenceTime)
    {
        if (!_states.TryGetValue(
                processId,
                out var state))
        {
            return [];
        }

        lock (state.Gate)
        {
            Cleanup(
                state,
                referenceTime);

            return state.Connections
                .Where(
                    connection =>
                        IsWithinWindow(
                            connection.DetectedAtUtc,
                            referenceTime))
                .OrderByDescending(
                    connection =>
                        connection.DetectedAtUtc)
                .ToArray();
        }
    }

    private bool IsWithinWindow(
        DateTimeOffset first,
        DateTimeOffset second)
    {
        var difference =
            (first - second).Duration();

        return difference <=
               _options.FileCorrelationWindow;
    }

    private void Cleanup(
        ProcessState state,
        DateTimeOffset referenceTime)
    {
        var cutoff =
            referenceTime -
            TimeSpan.FromTicks(
                _options.FileCorrelationWindow.Ticks *
                2);

        var oldFiles =
            state.Files
                .Where(
                    item =>
                        item.Value.LastReadAtUtc <
                        cutoff)
                .Select(
                    item =>
                        item.Key)
                .ToArray();

        foreach (var path in oldFiles)
        {
            state.Files.Remove(
                path);
        }

        state.Connections.RemoveAll(
            connection =>
                connection.DetectedAtUtc <
                cutoff);
    }

    private void TrimFiles(
        ProcessState state)
    {
        if (state.Files.Count <=
            _options.MaxTrackedFilesPerProcess)
        {
            return;
        }

        var remove =
            state.Files.Values
                .OrderBy(
                    file =>
                        file.LastReadAtUtc)
                .Take(
                    state.Files.Count -
                    _options.MaxTrackedFilesPerProcess)
                .Select(
                    file =>
                        file.FilePath)
                .ToArray();

        foreach (var path in remove)
        {
            state.Files.Remove(
                path);
        }
    }

    private sealed class ProcessState
    {
        public object Gate { get; } =
            new();

        public Dictionary<string, RecentFileRead> Files { get; } =
            new(
                StringComparer.OrdinalIgnoreCase);

        public List<NetworkConnectionObservation> Connections { get; } =
            [];
    }
}