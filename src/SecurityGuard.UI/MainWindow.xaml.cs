using System.Windows;
using System.Windows.Threading;
using SecurityGuard.UI.Services;
using SecurityGuard.UI.ViewModels;

namespace SecurityGuard.UI;

public partial class MainWindow
    : Window
{
    private readonly MainViewModel _viewModel;
    private readonly DispatcherTimer _refreshTimer;

    public MainWindow()
    {
        InitializeComponent();

        var notificationService =
            new DecisionNotificationService();

        _viewModel =
            new MainViewModel(
                new SecurityGuardClient(),
                notificationService);

        DataContext =
            _viewModel;

        _refreshTimer =
            new DispatcherTimer
            {
                Interval =
                    TimeSpan.FromSeconds(5)
            };

        _refreshTimer.Tick +=
            RefreshTimerOnTick;

        _refreshTimer.Start();

        Dispatcher.BeginInvoke(
            DispatcherPriority.Background,
            new Action(
                async () =>
                    await _viewModel.RefreshAsync()));

        Closed +=
            MainWindowOnClosed;
    }

    private async void RefreshTimerOnTick(
        object? sender,
        EventArgs e)
    {
        await _viewModel.RefreshAsync();
    }

    private void MainWindowOnClosed(
        object? sender,
        EventArgs e)
    {
        _refreshTimer.Stop();

        _refreshTimer.Tick -=
            RefreshTimerOnTick;
    }
}