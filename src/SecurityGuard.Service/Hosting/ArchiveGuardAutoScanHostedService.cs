using System.Collections.Concurrent;
using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.Service.Hosting;

public sealed class ArchiveGuardAutoScanHostedService
    : BackgroundService
{
    private readonly IArchiveGuardAutoScanSettingsService _settingsService;
    private readonly IArchiveGuardWatchDirectoryProvider _directoryProvider;
    private readonly IArchiveGuardFileCandidatePolicy _candidatePolicy;
    private readonly IArchiveGuardFileReadinessService _readinessService;
    private readonly IArchiveGuardWorkflowService _workflowService;
    private readonly IModuleRegistry _moduleRegistry;
    private readonly IAuditService _auditService;

    private readonly List<FileSystemWatcher> _watchers =
        [];

    private readonly ConcurrentDictionary<string, byte> _queuedPaths =
        new(
            StringComparer.OrdinalIgnoreCase);

    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastActivity =
        new(
            StringComparer.OrdinalIgnoreCase);

    private readonly ConcurrentDictionary<string, DateTimeOffset> _recentlyScanned =
        new(
            StringComparer.OrdinalIgnoreCase);

    private readonly ConcurrentDictionary<string, byte> _queuedRecoveryDirectories =
        new(
            StringComparer.OrdinalIgnoreCase);

    private readonly Channel<WatchWorkItem> _queue =
        Channel.CreateBounded<WatchWorkItem>(
            new BoundedChannelOptions(
                2048)
            {
                SingleWriter =
                    false,

                SingleReader =
                    false,

                FullMode =
                    BoundedChannelFullMode.DropWrite
            });

    private ArchiveGuardAutoScanSettings _settings =
        ArchiveGuardAutoScanSettings.Default;

    private int _processedSinceCleanup;

    public ArchiveGuardAutoScanHostedService(
        IArchiveGuardAutoScanSettingsService settingsService,
        IArchiveGuardWatchDirectoryProvider directoryProvider,
        IArchiveGuardFileCandidatePolicy candidatePolicy,
        IArchiveGuardFileReadinessService readinessService,
        IArchiveGuardWorkflowService workflowService,
        IModuleRegistry moduleRegistry,
        IAuditService auditService)
    {
        _settingsService =
            settingsService;

        _directoryProvider =
            directoryProvider;

        _candidatePolicy =
            candidatePolicy;

        _readinessService =
            readinessService;

        _workflowService =
            workflowService;

        _moduleRegistry =
            moduleRegistry;

        _auditService =
            auditService;
    }

    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        try
        {
            _settings =
                await _settingsService.GetAsync(
                    stoppingToken);

            if (!_settings.Enabled)
            {
                _moduleRegistry.Set(
                    SecurityModuleKind.ArchiveGuard,
                    ModuleOperationalState.Active,
                    "Manual scanning is active; automatic scanning is disabled");

                await Task.Delay(
                    Timeout.InfiniteTimeSpan,
                    stoppingToken);

                return;
            }

            var directories =
                _directoryProvider.GetDirectories(
                    _settings);

            foreach (var directory in
                     directories)
            {
                try
                {
                    _watchers.Add(
                        CreateWatcher(
                            directory));
                }
                catch (Exception exception)
                {
                    await _auditService.WriteAsync(
                        SecurityModuleKind.ArchiveGuard,
                        SecurityEventType.System,
                        SecuritySeverity.Medium,
                        "ArchiveGuard watcher could not start",
                        $"Directory={directory}; Error={exception.Message}",
                        cancellationToken:
                            stoppingToken);
                }
            }

            if (_watchers.Count == 0)
            {
                _moduleRegistry.Set(
                    SecurityModuleKind.ArchiveGuard,
                    ModuleOperationalState.Degraded,
                    "Manual scanning is active; no automatic scan directories are available");
            }
            else
            {
                _moduleRegistry.Set(
                    SecurityModuleKind.ArchiveGuard,
                    ModuleOperationalState.Active,
                    $"Automatic scanning is active for {_watchers.Count} directories");

                await _auditService.WriteAsync(
                    SecurityModuleKind.ArchiveGuard,
                    SecurityEventType.System,
                    SecuritySeverity.Info,
                    "ArchiveGuard automatic scanning started",
                    string.Join(
                        Environment.NewLine,
                        _watchers.Select(
                            watcher =>
                                watcher.Path)),
                    cancellationToken:
                        stoppingToken);
            }

            var workers =
                Enumerable.Range(
                        0,
                        _settings.WorkerCount)
                    .Select(
                        _ =>
                            ProcessQueueAsync(
                                stoppingToken))
                    .ToArray();

            await Task.WhenAll(
                workers);
        }
        catch (OperationCanceledException)
            when (stoppingToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            _moduleRegistry.Set(
                SecurityModuleKind.ArchiveGuard,
                ModuleOperationalState.Degraded,
                "Automatic scanning failed; manual scanning remains available");

            try
            {
                await _auditService.WriteAsync(
                    SecurityModuleKind.ArchiveGuard,
                    SecurityEventType.System,
                    SecuritySeverity.High,
                    "ArchiveGuard automatic scanning failed",
                    exception.Message,
                    cancellationToken:
                        CancellationToken.None);
            }
            catch
            {
            }

            try
            {
                await Task.Delay(
                    Timeout.InfiniteTimeSpan,
                    stoppingToken);
            }
            catch (OperationCanceledException)
                when (stoppingToken.IsCancellationRequested)
            {
            }
        }
        finally
        {
            foreach (var watcher in
                     _watchers)
            {
                watcher.EnableRaisingEvents =
                    false;

                watcher.Dispose();
            }

            _watchers.Clear();

            _moduleRegistry.Set(
                SecurityModuleKind.ArchiveGuard,
                ModuleOperationalState.Disabled,
                "ArchiveGuard is stopped");
        }
    }

    private FileSystemWatcher CreateWatcher(
        string directory)
    {
        var watcher =
            new FileSystemWatcher(
                directory)
            {
                Filter =
                    "*",

                IncludeSubdirectories =
                    false,

                NotifyFilter =
                    NotifyFilters.FileName |
                    NotifyFilters.CreationTime |
                    NotifyFilters.LastWrite |
                    NotifyFilters.Size,

                InternalBufferSize =
                    16 * 1024
            };

        watcher.Created +=
            OnFileChanged;

        watcher.Changed +=
            OnFileChanged;

        watcher.Renamed +=
            OnFileRenamed;

        watcher.Error +=
            OnWatcherError;

        watcher.EnableRaisingEvents =
            true;

        return watcher;
    }

    private void OnFileChanged(
        object sender,
        FileSystemEventArgs args)
    {
        QueueFile(
            args.FullPath);
    }

    private void OnFileRenamed(
        object sender,
        RenamedEventArgs args)
    {
        QueueFile(
            args.FullPath);
    }

    private void OnWatcherError(
        object sender,
        ErrorEventArgs args)
    {
        if (sender is not
            FileSystemWatcher watcher)
        {
            return;
        }

        QueueRecovery(
            watcher.Path,
            args.GetException().Message);
    }

    private void QueueFile(
        string filePath)
    {
        string fullPath;

        try
        {
            fullPath =
                Path.GetFullPath(
                    filePath);
        }
        catch
        {
            return;
        }

        if (!_candidatePolicy.ShouldScan(
                fullPath))
        {
            return;
        }

        var now =
            DateTimeOffset.UtcNow;

        if (_recentlyScanned.TryGetValue(
                fullPath,
                out var previousScan))
        {
            var age =
                now -
                previousScan;

            if (age <
                TimeSpan.FromSeconds(
                    _settings.DeduplicationWindowSeconds))
            {
                return;
            }

            _recentlyScanned.TryRemove(
                fullPath,
                out _);
        }

        _lastActivity[fullPath] =
            now;

        if (!_queuedPaths.TryAdd(
                fullPath,
                0))
        {
            return;
        }

        if (!_queue.Writer.TryWrite(
                new WatchWorkItem(
                    WatchWorkKind.File,
                    fullPath,
                    null)))
        {
            _queuedPaths.TryRemove(
                fullPath,
                out _);
        }
    }

    private void QueueRecovery(
        string directory,
        string error)
    {
        if (!_queuedRecoveryDirectories.TryAdd(
                directory,
                0))
        {
            return;
        }

        if (!_queue.Writer.TryWrite(
                new WatchWorkItem(
                    WatchWorkKind.Recovery,
                    directory,
                    error)))
        {
            _queuedRecoveryDirectories.TryRemove(
                directory,
                out _);
        }
    }

    private async Task ProcessQueueAsync(
        CancellationToken cancellationToken)
    {
        await foreach (
            var item in
            _queue.Reader.ReadAllAsync(
                cancellationToken))
        {
            if (item.Kind ==
                WatchWorkKind.Recovery)
            {
                await ProcessRecoveryAsync(
                    item,
                    cancellationToken);

                continue;
            }

            await ProcessFileAsync(
                item.Path,
                cancellationToken);
        }
    }

    private async Task ProcessFileAsync(
        string filePath,
        CancellationToken cancellationToken)
    {
        var initialActivity =
            _lastActivity.TryGetValue(
                filePath,
                out var initial)
                ? initial
                : DateTimeOffset.UtcNow;

        DateTimeOffset? readyActivity =
            null;

        try
        {
            if (!await WaitForQuietPeriodAsync(
                    filePath,
                    cancellationToken))
            {
                return;
            }

            if (!await _readinessService.WaitUntilStableAsync(
                    filePath,
                    _settings,
                    cancellationToken))
            {
                return;
            }

            if (!File.Exists(
                    filePath))
            {
                return;
            }

            readyActivity =
                _lastActivity.TryGetValue(
                    filePath,
                    out var current)
                    ? current
                    : DateTimeOffset.UtcNow;

            await _workflowService.ScanAsync(
                filePath,
                cancellationToken);

            _recentlyScanned[filePath] =
                DateTimeOffset.UtcNow;
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (FileNotFoundException)
        {
        }
        catch (DirectoryNotFoundException)
        {
        }
        catch (Exception exception)
        {
            await _auditService.WriteAsync(
                SecurityModuleKind.ArchiveGuard,
                SecurityEventType.FileScan,
                SecuritySeverity.High,
                "Automatic ArchiveGuard scan failed",
                $"File={filePath}; Error={exception.Message}",
                cancellationToken:
                    cancellationToken);
        }
        finally
        {
            _queuedPaths.TryRemove(
                filePath,
                out _);

            if (_lastActivity.TryGetValue(
                    filePath,
                    out var latestActivity))
            {
                var comparison =
                    readyActivity ??
                    initialActivity;

                _lastActivity.TryRemove(
                    filePath,
                    out _);

                if (latestActivity >
                        comparison &&
                    File.Exists(
                        filePath))
                {
                    _recentlyScanned.TryRemove(
                        filePath,
                        out _);

                    QueueFile(
                        filePath);
                }
            }

            CleanupRecentScans();
        }
    }

    private async Task<bool> WaitForQuietPeriodAsync(
        string filePath,
        CancellationToken cancellationToken)
    {
        var timeout =
            DateTimeOffset.UtcNow +
            TimeSpan.FromSeconds(
                _settings.ReadyTimeoutSeconds);

        var quietPeriod =
            TimeSpan.FromMilliseconds(
                _settings.QuietPeriodMilliseconds);

        while (DateTimeOffset.UtcNow <
               timeout)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!File.Exists(
                    filePath))
            {
                return false;
            }

            var lastActivity =
                _lastActivity.TryGetValue(
                    filePath,
                    out var value)
                    ? value
                    : DateTimeOffset.UtcNow;

            var remaining =
                quietPeriod -
                (DateTimeOffset.UtcNow -
                 lastActivity);

            if (remaining <=
                TimeSpan.Zero)
            {
                return true;
            }

            var delay =
                remaining >
                TimeSpan.FromMilliseconds(
                    500)
                    ? TimeSpan.FromMilliseconds(
                        500)
                    : remaining;

            await Task.Delay(
                delay,
                cancellationToken);
        }

        return false;
    }

    private async Task ProcessRecoveryAsync(
        WatchWorkItem item,
        CancellationToken cancellationToken)
    {
        try
        {
            await _auditService.WriteAsync(
                SecurityModuleKind.ArchiveGuard,
                SecurityEventType.System,
                SecuritySeverity.Medium,
                "ArchiveGuard watcher recovery scan",
                $"Directory={item.Path}; Error={item.Error ?? "Unknown"}",
                cancellationToken:
                    cancellationToken);

            if (!Directory.Exists(
                    item.Path))
            {
                return;
            }

            var cutoff =
                DateTime.UtcNow -
                TimeSpan.FromMinutes(
                    _settings.RecoveryLookbackMinutes);

            foreach (var file in
                     Directory.EnumerateFiles(
                         item.Path,
                         "*",
                         SearchOption.TopDirectoryOnly))
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    if (File.GetLastWriteTimeUtc(
                            file) <
                        cutoff)
                    {
                        continue;
                    }

                    QueueFile(
                        file);
                }
                catch
                {
                }
            }
        }
        finally
        {
            _queuedRecoveryDirectories.TryRemove(
                item.Path,
                out _);
        }
    }

    private void CleanupRecentScans()
    {
        if (Interlocked.Increment(
                ref _processedSinceCleanup) <
            100)
        {
            return;
        }

        Interlocked.Exchange(
            ref _processedSinceCleanup,
            0);

        var retention =
            TimeSpan.FromSeconds(
                Math.Max(
                    120,
                    _settings.DeduplicationWindowSeconds *
                    4));

        var cutoff =
            DateTimeOffset.UtcNow -
            retention;

        foreach (var pair in
                 _recentlyScanned)
        {
            if (pair.Value <
                cutoff)
            {
                _recentlyScanned.TryRemove(
                    pair.Key,
                    out _);
            }
        }
    }

    private enum WatchWorkKind
    {
        File = 0,
        Recovery = 1
    }

    private sealed record WatchWorkItem(
        WatchWorkKind Kind,
        string Path,
        string? Error);
}