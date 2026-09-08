using System.Collections.ObjectModel;
using System.Windows.Input;
using SecurityGuard.AlgorithmGuard.Enums;
using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;
using SecurityGuard.UI.Services;
using Microsoft.Win32;
using SecurityGuard.Core.Ipc.ArchiveGuard;

namespace SecurityGuard.UI.ViewModels;

public sealed class MainViewModel
    : ViewModelBase
{
    private readonly ISecurityGuardClient _client;

    private int _selectedPageIndex;
    private bool _isBusy;
    private bool _isConnected;
    private string? _lastError;
    private int _quarantineCount;
    private DateTimeOffset? _lastRefreshUtc;

    private bool _algorithmGuardEnabled;

    private AlgorithmGuardMode _algorithmGuardMode =
        AlgorithmGuardMode.Monitor;

    private EnforcementFailurePolicy _algorithmGuardFailurePolicy =
        EnforcementFailurePolicy.FailOpen;

    private bool _transferGuardEnabled;

    private TransferGuardMode _transferGuardMode =
        TransferGuardMode.Monitor;

    private TransferEnforcementFailurePolicy _transferGuardFailurePolicy =
        TransferEnforcementFailurePolicy.FailOpen;
    
    private string? _archiveFilePath;

    private ArchiveGuardScanIpcDto? _archiveScanResult;

    private string _archiveStatusText =
        "Выберите файл для проверки.";

    private bool _archiveDecisionResolved;

    public ObservableCollection<ModuleStatus> Modules { get; } =
        [];

    public ObservableCollection<SecurityEvent> RecentEvents { get; } =
        [];

    public ObservableCollection<SecurityEvent> AlgorithmEvents { get; } =
        [];

    public ObservableCollection<SecurityEvent> TransferEvents { get; } =
        [];

    public ObservableCollection<SecurityEvent> ArchiveEvents { get; } =
        [];
    
    public ObservableCollection<ArchiveGuardFindingIpcDto> ArchiveFindings { get; } =
        [];

    public ObservableCollection<ArchiveGuardRecentScanIpcDto> ArchiveScanHistory { get; } =
        [];

    public ObservableCollection<DecisionRequestViewModel> PendingRequests { get; } =
        [];

    public ObservableCollection<SecurityRuleViewModel> Rules { get; } =
        [];

    public ObservableCollection<SecurityRuleViewModel> AllowRules { get; } =
        [];

    public ObservableCollection<SecurityRuleViewModel> BlockRules { get; } =
        [];

    public ICommand NavigateCommand { get; }

    public ICommand RefreshCommand { get; }

    public ICommand SaveAlgorithmGuardSettingsCommand { get; }

    public ICommand SaveTransferGuardSettingsCommand { get; }

    public ICommand SelectArchiveFileCommand { get; }

    public ICommand ScanArchiveFileCommand { get; }

    public ICommand RefreshArchiveHistoryCommand { get; }

    public ICommand ArchiveKeepCommand { get; }

    public ICommand ArchiveAddExceptionCommand { get; }

    public ICommand ArchiveQuarantineCommand { get; }

    public ICommand ArchiveDeleteCommand { get; }

    public IReadOnlyList<AlgorithmGuardMode> AlgorithmGuardModes { get; } =
        Enum.GetValues<AlgorithmGuardMode>();

    public IReadOnlyList<EnforcementFailurePolicy> AlgorithmGuardFailurePolicies { get; } =
        Enum.GetValues<EnforcementFailurePolicy>();

    public IReadOnlyList<TransferGuardMode> TransferGuardModes { get; } =
        Enum.GetValues<TransferGuardMode>();

    public IReadOnlyList<TransferEnforcementFailurePolicy> TransferGuardFailurePolicies { get; } =
        Enum.GetValues<TransferEnforcementFailurePolicy>();

    public int SelectedPageIndex
    {
        get =>
            _selectedPageIndex;

        set =>
            SetProperty(
                ref _selectedPageIndex,
                value);
    }

    public bool IsBusy
    {
        get =>
            _isBusy;

        private set =>
            SetProperty(
                ref _isBusy,
                value);
    }

    public bool IsConnected
    {
        get =>
            _isConnected;

        private set
        {
            if (SetProperty(
                    ref _isConnected,
                    value))
            {
                OnPropertyChanged(
                    nameof(ServiceStatus));
            }
        }
    }

    public string ServiceStatus =>
        IsConnected
            ? "Служба подключена"
            : "Служба недоступна";

    public string? LastError
    {
        get =>
            _lastError;

        private set
        {
            if (SetProperty(
                    ref _lastError,
                    value))
            {
                OnPropertyChanged(
                    nameof(HasError));
            }
        }
    }

    public bool HasError =>
        !string.IsNullOrWhiteSpace(
            LastError);

    public int QuarantineCount
    {
        get =>
            _quarantineCount;

        private set =>
            SetProperty(
                ref _quarantineCount,
                value);
    }

    public DateTimeOffset? LastRefreshUtc
    {
        get =>
            _lastRefreshUtc;

        private set =>
            SetProperty(
                ref _lastRefreshUtc,
                value);
    }

    public bool AlgorithmGuardEnabled
    {
        get =>
            _algorithmGuardEnabled;

        set =>
            SetProperty(
                ref _algorithmGuardEnabled,
                value);
    }

    public AlgorithmGuardMode AlgorithmGuardMode
    {
        get =>
            _algorithmGuardMode;

        set =>
            SetProperty(
                ref _algorithmGuardMode,
                value);
    }

    public EnforcementFailurePolicy AlgorithmGuardFailurePolicy
    {
        get =>
            _algorithmGuardFailurePolicy;

        set =>
            SetProperty(
                ref _algorithmGuardFailurePolicy,
                value);
    }

    public bool TransferGuardEnabled
    {
        get =>
            _transferGuardEnabled;

        set =>
            SetProperty(
                ref _transferGuardEnabled,
                value);
    }

    public TransferGuardMode TransferGuardMode
    {
        get =>
            _transferGuardMode;

        set =>
            SetProperty(
                ref _transferGuardMode,
                value);
    }

    public TransferEnforcementFailurePolicy TransferGuardFailurePolicy
    {
        get =>
            _transferGuardFailurePolicy;

        set =>
            SetProperty(
                ref _transferGuardFailurePolicy,
                value);
    }

    public MainViewModel(
        ISecurityGuardClient client)
    {
        _client =
            client;

        NavigateCommand =
            new RelayCommand(
                Navigate);

        RefreshCommand =
            new AsyncRelayCommand(
                RefreshAsync,
                () => !IsBusy);

        SaveAlgorithmGuardSettingsCommand =
            new AsyncRelayCommand(
                SaveAlgorithmGuardSettingsAsync);

        SaveTransferGuardSettingsCommand =
            new AsyncRelayCommand(
                SaveTransferGuardSettingsAsync);
        
        SelectArchiveFileCommand =
            new RelayCommand(
                SelectArchiveFile,
                _ =>
                    !IsBusy);

        ScanArchiveFileCommand =
            new AsyncRelayCommand(
                ScanArchiveFileAsync,
                () =>
                    !IsBusy &&
                    !string.IsNullOrWhiteSpace(
                        ArchiveFilePath));

        RefreshArchiveHistoryCommand =
            new AsyncRelayCommand(
                RefreshArchiveHistoryAsync,
                () =>
                    !IsBusy);

        ArchiveKeepCommand =
            new AsyncRelayCommand(
                () =>
                    SubmitArchiveDecisionAsync(
                        SecurityAction.AllowOnce),
                () =>
                    CanApplyArchiveAction(
                        SecurityAction.AllowOnce));

        ArchiveAddExceptionCommand =
            new AsyncRelayCommand(
                () =>
                    SubmitArchiveDecisionAsync(
                        SecurityAction.Allow),
                () =>
                    CanApplyArchiveAction(
                        SecurityAction.Allow));

        ArchiveQuarantineCommand =
            new AsyncRelayCommand(
                () =>
                    SubmitArchiveDecisionAsync(
                        SecurityAction.Quarantine),
                () =>
                    CanApplyArchiveAction(
                        SecurityAction.Quarantine));

        ArchiveDeleteCommand =
            new AsyncRelayCommand(
                () =>
                    SubmitArchiveDecisionAsync(
                        SecurityAction.Delete),
                () =>
                    CanApplyArchiveAction(
                        SecurityAction.Delete));
    }

    public async Task RefreshAsync()
    {
        if (IsBusy)
        {
            return;
        }

        IsBusy =
            true;

        try
        {
            var connected =
                await _client.PingAsync();

            if (!connected)
            {
                IsConnected =
                    false;

                LastError =
                    "SecurityGuard.Service не отвечает.";

                return;
            }

            var snapshotTask =
                _client.GetSnapshotAsync();

            var rulesTask =
                _client.GetRulesAsync();

            var algorithmSettingsTask =
                _client.GetAlgorithmGuardSettingsAsync();

            var transferSettingsTask =
                _client.GetTransferGuardSettingsAsync();

            await Task.WhenAll(
                snapshotTask,
                rulesTask,
                algorithmSettingsTask,
                transferSettingsTask);

            var snapshot =
                await snapshotTask;

            var rules =
                await rulesTask;

            var algorithmSettings =
                await algorithmSettingsTask;

            var transferSettings =
                await transferSettingsTask;

            IsConnected =
                true;

            LastError =
                null;

            UpdateSnapshot(
                snapshot);

            UpdateRules(
                rules);

            ApplyAlgorithmGuardSettings(
                algorithmSettings);

            ApplyTransferGuardSettings(
                transferSettings);

            LastRefreshUtc =
                DateTimeOffset.UtcNow;
        }
        catch (Exception exception)
        {
            IsConnected =
                false;

            LastError =
                exception.Message;
        }
        finally
        {
            IsBusy =
                false;

            if (RefreshCommand is
                AsyncRelayCommand command)
            {
                command.RaiseCanExecuteChanged();
            }
        }
    }

    private void UpdateSnapshot(
        SecuritySnapshot snapshot)
    {
        Replace(
            Modules,
            snapshot.Modules);

        Replace(
            RecentEvents,
            snapshot.RecentEvents);

        Replace(
            AlgorithmEvents,
            snapshot.RecentEvents.Where(
                item =>
                    item.Module ==
                    SecurityModuleKind.AlgorithmGuard));

        Replace(
            TransferEvents,
            snapshot.RecentEvents.Where(
                item =>
                    item.Module ==
                    SecurityModuleKind.TransferGuard));

        Replace(
            ArchiveEvents,
            snapshot.RecentEvents.Where(
                item =>
                    item.Module ==
                    SecurityModuleKind.ArchiveGuard));

        PendingRequests.Clear();

        foreach (var request in
                 snapshot.PendingRequests)
        {
            PendingRequests.Add(
                new DecisionRequestViewModel(
                    request,
                    SubmitDecisionAsync));
        }

        QuarantineCount =
            snapshot.QuarantineCount;
    }

    private async Task SubmitDecisionAsync(
        Guid requestId,
        SecurityAction action)
    {
        try
        {
            var decision =
                new SecurityDecision(
                    requestId,
                    action,
                    action ==
                    SecurityAction.Allow,
                    DateTimeOffset.UtcNow);

            await _client.SubmitDecisionAsync(
                decision);

            LastError =
                null;

            await RefreshAsync();
        }
        catch (Exception exception)
        {
            LastError =
                exception.Message;
        }
    }

    private void Navigate(
        object? parameter)
    {
        if (parameter is null)
        {
            return;
        }

        if (int.TryParse(
                parameter.ToString(),
                out var index))
        {
            SelectedPageIndex =
                index;
        }
    }

    private void UpdateRules(
        IReadOnlyList<SecurityRule> rules)
    {
        var viewModels =
            rules
                .Select(
                    rule =>
                        new SecurityRuleViewModel(
                            rule,
                            DeleteRuleAsync))
                .ToArray();

        Replace(
            Rules,
            viewModels);

        Replace(
            AllowRules,
            viewModels.Where(
                rule =>
                    rule.Decision ==
                    RuleDecision.Allow));

        Replace(
            BlockRules,
            viewModels.Where(
                rule =>
                    rule.Decision ==
                    RuleDecision.Block));
    }

    private async Task DeleteRuleAsync(
        Guid ruleId)
    {
        try
        {
            await _client.DeleteRuleAsync(
                ruleId);

            LastError =
                null;

            await RefreshAsync();
        }
        catch (Exception exception)
        {
            LastError =
                exception.Message;
        }
    }

    private void ApplyAlgorithmGuardSettings(
        AlgorithmGuardSettings settings)
    {
        AlgorithmGuardEnabled =
            settings.Enabled;

        AlgorithmGuardMode =
            settings.Mode;

        AlgorithmGuardFailurePolicy =
            settings.FailurePolicy;
    }

    private async Task SaveAlgorithmGuardSettingsAsync()
    {
        try
        {
            var settings =
                new AlgorithmGuardSettings(
                    AlgorithmGuardEnabled,
                    AlgorithmGuardMode,
                    AlgorithmGuardFailurePolicy);

            await _client.UpdateAlgorithmGuardSettingsAsync(
                settings);

            LastError =
                null;

            await RefreshAsync();
        }
        catch (Exception exception)
        {
            LastError =
                exception.Message;
        }
    }

    private void ApplyTransferGuardSettings(
        TransferGuardSettings settings)
    {
        TransferGuardEnabled =
            settings.Enabled;

        TransferGuardMode =
            settings.Mode;

        TransferGuardFailurePolicy =
            settings.FailurePolicy;
    }

    private async Task SaveTransferGuardSettingsAsync()
    {
        try
        {
            var settings =
                new TransferGuardSettings(
                    TransferGuardEnabled,
                    TransferGuardMode,
                    TransferGuardFailurePolicy);

            await _client.UpdateTransferGuardSettingsAsync(
                settings);

            LastError =
                null;

            await RefreshAsync();
        }
        catch (Exception exception)
        {
            LastError =
                exception.Message;
        }
    }

    private void SelectArchiveFile(
        object? parameter)
    {
        var dialog =
            new OpenFileDialog
            {
                Title =
                    "Выберите файл для проверки",

                Filter =
                    "Все файлы|*.*",

                CheckFileExists =
                    true,

                CheckPathExists =
                    true,

                Multiselect =
                    false
            };

        if (dialog.ShowDialog() !=
            true)
        {
            return;
        }

        ArchiveFilePath =
            dialog.FileName;

        ArchiveStatusText =
            "Файл выбран.";
    }

    private async Task ScanArchiveFileAsync()
    {
        if (string.IsNullOrWhiteSpace(
                ArchiveFilePath))
        {
            return;
        }

        IsBusy =
            true;

        _archiveDecisionResolved =
            false;

        OnPropertyChanged(
            nameof(ArchiveHasPendingDecision));

        ArchiveStatusText =
            "Проверка файла...";

        try
        {
            var result =
                await _client.ScanArchiveGuardAsync(
                    ArchiveFilePath);

            ArchiveScanResult =
                result;

            Replace(
                ArchiveFindings,
                result.Findings);

            ArchiveStatusText =
                GetArchiveStatusText(
                    result.Verdict);

            var history =
                await _client.GetArchiveGuardRecentScansAsync(
                    50);

            Replace(
                ArchiveScanHistory,
                history);

            LastError =
                null;
        }
        catch (Exception exception)
        {
            LastError =
                exception.Message;

            ArchiveStatusText =
                "Проверка не выполнена.";
        }
        finally
        {
            IsBusy =
                false;

            RaiseArchiveCommandStates();
        }
    }

    private async Task RefreshArchiveHistoryAsync()
    {
        try
        {
            var history =
                await _client.GetArchiveGuardRecentScansAsync(
                    50);

            Replace(
                ArchiveScanHistory,
                history);

            LastError =
                null;
        }
        catch (Exception exception)
        {
            LastError =
                exception.Message;
        }
    }

    private async Task SubmitArchiveDecisionAsync(
        SecurityAction action)
    {
        var requestId =
            ArchiveScanResult?.DecisionRequestId;

        if (requestId is null ||
            _archiveDecisionResolved)
        {
            return;
        }

        IsBusy =
            true;

        try
        {
            var decision =
                new SecurityDecision(
                    requestId.Value,
                    action,
                    action ==
                    SecurityAction.Allow,
                    DateTimeOffset.UtcNow);

            await _client.SubmitDecisionAsync(
                decision);

            _archiveDecisionResolved =
                true;

            OnPropertyChanged(
                nameof(ArchiveHasPendingDecision));

            ArchiveStatusText =
                GetArchiveActionStatus(
                    action);

            LastError =
                null;
        }
        catch (Exception exception)
        {
            LastError =
                exception.Message;
        }
        finally
        {
            IsBusy =
                false;

            RaiseArchiveCommandStates();
        }

        await RefreshAsync();
    }

    private bool CanApplyArchiveAction(
        SecurityAction action)
    {
        return !IsBusy &&
            ArchiveHasPendingDecision &&
            ArchiveScanResult is not null &&
            ArchiveScanResult.AvailableActions.Contains(
                action);
    }

    private void RaiseArchiveCommandStates()
    {
        if (SelectArchiveFileCommand is
            RelayCommand selectCommand)
        {
            selectCommand.RaiseCanExecuteChanged();
        }

        if (ScanArchiveFileCommand is
            AsyncRelayCommand scanCommand)
        {
            scanCommand.RaiseCanExecuteChanged();
        }

        if (RefreshArchiveHistoryCommand is
            AsyncRelayCommand historyCommand)
        {
            historyCommand.RaiseCanExecuteChanged();
        }

        RaiseArchiveActionCommand(
            ArchiveKeepCommand);

        RaiseArchiveActionCommand(
            ArchiveAddExceptionCommand);

        RaiseArchiveActionCommand(
            ArchiveQuarantineCommand);

        RaiseArchiveActionCommand(
            ArchiveDeleteCommand);
    }

    private static void RaiseArchiveActionCommand(
        ICommand command)
    {
        if (command is
            AsyncRelayCommand asyncCommand)
        {
            asyncCommand.RaiseCanExecuteChanged();
        }
    }

    private static string GetArchiveStatusText(
        ScanVerdict verdict)
    {
        return verdict switch
        {
            ScanVerdict.Clean =>
                "Угроз не обнаружено.",

            ScanVerdict.Suspicious =>
                "Обнаружены подозрительные признаки.",

            ScanVerdict.Malicious =>
                "Обнаружен вредоносный файл.",

            ScanVerdict.Unknown =>
                "Файл не удалось проверить полностью.",

            ScanVerdict.Error =>
                "Проверка завершилась с ошибкой.",

            _ =>
                "Проверка завершена."
        };
    }

    private static string GetArchiveActionStatus(
        SecurityAction action)
    {
        return action switch
        {
            SecurityAction.AllowOnce =>
                "Файл оставлен.",

            SecurityAction.Allow =>
                "Добавлено исключение по SHA-256.",

            SecurityAction.Quarantine =>
                "Файл перемещён в карантин.",

            SecurityAction.Delete =>
                "Файл удалён.",

            _ =>
                "Действие выполнено."
        };
    }

    private static void Replace<T>(
        ObservableCollection<T> collection,
        IEnumerable<T> values)
    {
        collection.Clear();

        foreach (var value in
                 values)
        {
            collection.Add(
                value);
        }
    }

    public string? ArchiveFilePath
    {
        get =>
            _archiveFilePath;

        set
        {
            if (SetProperty(
                    ref _archiveFilePath,
                    value))
            {
                RaiseArchiveCommandStates();
            }
        }
    }

    public ArchiveGuardScanIpcDto? ArchiveScanResult
    {
        get =>
            _archiveScanResult;

        private set
        {
            if (SetProperty(
                    ref _archiveScanResult,
                    value))
            {
                OnPropertyChanged(
                    nameof(ArchiveHasPendingDecision));

                RaiseArchiveCommandStates();
            }
        }
    }

    public string ArchiveStatusText
    {
        get =>
            _archiveStatusText;

        private set =>
            SetProperty(
                ref _archiveStatusText,
                value);
    }

    public bool ArchiveHasPendingDecision =>
        ArchiveScanResult?.DecisionRequestId is not null &&
        !_archiveDecisionResolved;
}