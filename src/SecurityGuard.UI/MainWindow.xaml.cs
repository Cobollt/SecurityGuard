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

        _viewModel =
            new MainViewModel(
                new SecurityGuardClient());

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

        Loaded +=
            MainWindowOnLoaded;

        Closed +=
            MainWindowOnClosed;
    }

    private async void MainWindowOnLoaded(
        object sender,
        RoutedEventArgs e)
    {
        await _viewModel.RefreshAsync();

        _refreshTimer.Start();
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