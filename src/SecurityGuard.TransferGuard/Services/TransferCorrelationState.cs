using System.Collections.Concurrent;
using SecurityGuard.TransferGuard.Configuration;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Enums;
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
        if (activity.Classification?.Priority ==
            TransferFilePriority.Ignore)
        {
            return;
        }

        var state =
            GetState(
                activity.ProcessId,
                activity.ProcessInstance);

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
                            activity.ReadAtUtc,

                        Classification =
                            ChooseClassification(
                                existing.Classification,
                                activity.Classification)
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
                        activity.ReadAtUtc,
                        activity.Classification);
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
            GetState(
                processId.Value,
                observation.ProcessInstance);

        lock (state.Gate)
        {
            Cleanup(
                state,
                observation.DetectedAtUtc);

            state.Connections.Add(
                observation);

            TrimConnections(
                state);
        }
    }

    public void RecordNetworkSend(
        NetworkSendActivity activity)
    {
        ArgumentNullException.ThrowIfNull(
            activity);

        if (activity.ProcessId <= 0 ||
            activity.BytesSent <= 0)
        {
            return;
        }

        var state =
            GetState(
                activity.ProcessId,
                activity.ProcessInstance);

        lock (state.Gate)
        {
            Cleanup(
                state,
                activity.SentAtUtc);

            var key =
                new NetworkDestinationKey(
                    activity.Protocol,
                    activity.AddressFamily,
                    activity.LocalAddress,
                    activity.LocalPort,
                    activity.RemoteAddress,
                    activity.RemotePort);

            if (state.NetworkSends.TryGetValue(
                    key,
                    out var existing))
            {
                state.NetworkSends[key] =
                    existing with
                    {
                        ObservedSentBytes =
                            existing.ObservedSentBytes +
                            activity.BytesSent,

                        LastSendAtUtc =
                            activity.SentAtUtc
                    };
            }
            else
            {
                state.NetworkSends[key] =
                    new RecentNetworkSend(
                        activity.ProcessId,
                        activity.Protocol,
                        activity.AddressFamily,
                        activity.LocalAddress,
                        activity.LocalPort,
                        activity.RemoteAddress,
                        activity.RemotePort,
                        activity.BytesSent,
                        activity.SentAtUtc,
                        activity.SentAtUtc);
            }

            TrimNetworkSends(
                state);
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
                    item =>
                        IsWithinWindow(
                            item.LastReadAtUtc,
                            referenceTime))
                .OrderByDescending(
                    item =>
                        GetPriority(
                            item))
                .ThenByDescending(
                    item =>
                        item.LastReadAtUtc)
                .ThenByDescending(
                    item =>
                        item.ObservedReadBytes)
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
                    item =>
                        IsWithinWindow(
                            item.DetectedAtUtc,
                            referenceTime))
                .OrderByDescending(
                    item =>
                        item.DetectedAtUtc)
                .ToArray();
        }
    }

    public IReadOnlyList<RecentNetworkSend> GetRecentNetworkSends(
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

            return state.NetworkSends.Values
                .Where(
                    item =>
                        IsWithinWindow(
                            item.LastSendAtUtc,
                            referenceTime))
                .OrderByDescending(
                    item =>
                        item.LastSendAtUtc)
                .ToArray();
        }
    }

    private ProcessState GetState(
        int processId)
    {
        return _states.GetOrAdd(
            processId,
            _ =>
                new ProcessState());
    }

    private bool IsWithinWindow(
        DateTimeOffset first,
        DateTimeOffset second)
    {
        return (first - second)
                   .Duration() <=
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

        foreach (var key in oldFiles)
        {
            state.Files.Remove(
                key);
        }

        state.Connections.RemoveAll(
            item =>
                item.DetectedAtUtc <
                cutoff);

        var oldNetworkSends =
            state.NetworkSends
                .Where(
                    item =>
                        item.Value.LastSendAtUtc <
                        cutoff)
                .Select(
                    item =>
                        item.Key)
                .ToArray();

        foreach (var key in oldNetworkSends)
        {
            state.NetworkSends.Remove(
                key);
        }
    }

    private void TrimFiles(
        ProcessState state)
    {
        var overflow =
            state.Files.Count -
            _options.MaxTrackedFilesPerProcess;

        if (overflow <= 0)
        {
            return;
        }

        var remove =
            state.Files.Values
                .OrderBy(
                    item =>
                        GetPriority(
                            item))
                .ThenBy(
                    item =>
                        item.LastReadAtUtc)
                .Take(
                    overflow)
                .Select(
                    item =>
                        item.FilePath)
                .ToArray();

        foreach (var key in remove)
        {
            state.Files.Remove(
                key);
        }
    }

    private void TrimConnections(
        ProcessState state)
    {
        var overflow =
            state.Connections.Count -
            _options.MaxTrackedConnectionsPerProcess;

        if (overflow <= 0)
        {
            return;
        }

        state.Connections.RemoveRange(
            0,
            overflow);
    }

    private void TrimNetworkSends(
        ProcessState state)
    {
        var overflow =
            state.NetworkSends.Count -
            _options.MaxTrackedNetworkDestinationsPerProcess;

        if (overflow <= 0)
        {
            return;
        }

        var remove =
            state.NetworkSends
                .OrderBy(
                    item =>
                        item.Value.LastSendAtUtc)
                .Take(
                    overflow)
                .Select(
                    item =>
                        item.Key)
                .ToArray();

        foreach (var key in remove)
        {
            state.NetworkSends.Remove(
                key);
        }
    }

    private sealed class ProcessState
    {
        public object Gate { get; } =
            new();

        public TransferProcessInstanceId? ProcessInstance { get; set; }

        public Dictionary<string, RecentFileRead> Files { get; } =
            new(
                StringComparer.OrdinalIgnoreCase);

        public List<NetworkConnectionObservation> Connections { get; } =
            [];

        public Dictionary<
            NetworkDestinationKey,
            RecentNetworkSend> NetworkSends { get; } =
            [];
    }

    private sealed record NetworkDestinationKey(
        TransferProtocol Protocol,
        NetworkAddressFamily AddressFamily,
        string LocalAddress,
        int LocalPort,
        string RemoteAddress,
        int RemotePort);

    private static TransferFileClassification? ChooseClassification(
        TransferFileClassification? first,
        TransferFileClassification? second)
    {
        if (first is null)
        {
            return second;
        }

        if (second is null)
        {
            return first;
        }

        return second.Priority >
            first.Priority
            ? second
            : first;
    }

        private static int GetPriority(
        RecentFileRead file)
    {
        return (int)(
            file.Classification?.Priority ??
            TransferFilePriority.Low);
    }

    private ProcessState GetState(
        int processId,
        TransferProcessInstanceId? processInstance)
    {
        var state =
            _states.GetOrAdd(
                processId,
                _ =>
                    new ProcessState());

        lock (state.Gate)
        {
            EnsureProcessInstance(
                state,
                processInstance);
        }

        return state;
    }

    private static void EnsureProcessInstance(
        ProcessState state,
        TransferProcessInstanceId? processInstance)
    {
        if (processInstance is null)
        {
            return;
        }

        if (state.ProcessInstance is null)
        {
            state.ProcessInstance =
                processInstance;

            return;
        }

        if (state.ProcessInstance ==
            processInstance)
        {
            return;
        }

        ClearState(
            state);

        state.ProcessInstance =
            processInstance;
    }

    private static void ClearState(
        ProcessState state)
    {
        state.Files.Clear();
        state.Connections.Clear();
        state.NetworkSends.Clear();
    }

    public void ResetProcess(
        TransferProcessInstanceId processInstance)
    {
        var state =
            _states.GetOrAdd(
                processInstance.ProcessId,
                _ =>
                    new ProcessState());

        lock (state.Gate)
        {
            ClearState(
                state);

            state.ProcessInstance =
                processInstance;
        }
    }

    public void RemoveProcess(
        TransferProcessInstanceId processInstance)
    {
        if (!_states.TryGetValue(
                processInstance.ProcessId,
                out var state))
        {
            return;
        }

        lock (state.Gate)
        {
            if (state.ProcessInstance is not null &&
                state.ProcessInstance !=
                processInstance)
            {
                return;
            }
        }

        _states.TryRemove(
            processInstance.ProcessId,
            out _);
    }

    public IReadOnlyList<int> GetTrackedProcessIds()
    {
        return _states.Keys
            .ToArray();
    }
}