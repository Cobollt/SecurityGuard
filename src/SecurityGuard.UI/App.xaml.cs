using System.ComponentModel;
using System.Drawing;
using System.Threading;
using System.Windows;
using Forms = System.Windows.Forms;

namespace SecurityGuard.UI;

public partial class App
    : System.Windows.Application
{
    private const string MutexName =
        @"Local\SecurityGuard.UI.Singleton";

    private const string ShowWindowEventName =
        @"Local\SecurityGuard.UI.ShowWindow";

    private readonly EventWaitHandle _shutdownEvent =
        new(
            false,
            EventResetMode.ManualReset);

    private Mutex? _instanceMutex;
    private EventWaitHandle? _showWindowEvent;
    private Thread? _listenerThread;
    private Forms.NotifyIcon? _trayIcon;

    private bool _ownsMutex;
    private bool _isExiting;

    protected override void OnStartup(
        StartupEventArgs e)
    {
        base.OnStartup(
            e);

        var startInBackground =
            e.Args.Any(
                argument =>
                    string.Equals(
                        argument,
                        "--background",
                        StringComparison.OrdinalIgnoreCase));

        _instanceMutex =
            new Mutex(
                false,
                MutexName);

        try
        {
            _ownsMutex =
                _instanceMutex.WaitOne(
                    0,
                    false);
        }
        catch (AbandonedMutexException)
        {
            _ownsMutex =
                true;
        }

        if (!_ownsMutex)
        {
            if (!startInBackground)
            {
                using var showEvent =
                    new EventWaitHandle(
                        false,
                        EventResetMode.AutoReset,
                        ShowWindowEventName);

                showEvent.Set();
            }

            Shutdown();
            return;
        }

        ShutdownMode =
            ShutdownMode.OnExplicitShutdown;

        InitializeInstanceListener();
        InitializeTrayIcon();

        var window =
            new MainWindow();

        MainWindow =
            window;

        window.Closing +=
            OnMainWindowClosing;

        if (!startInBackground)
        {
            ShowMainWindow();
        }
    }

    private void InitializeInstanceListener()
    {
        _showWindowEvent =
            new EventWaitHandle(
                false,
                EventResetMode.AutoReset,
                ShowWindowEventName);

        _listenerThread =
            new Thread(
                ListenForInstanceCommands)
            {
                IsBackground =
                    true,
                Name =
                    "SecurityGuard.UI.InstanceListener"
            };

        _listenerThread.Start();
    }

    private void ListenForInstanceCommands()
    {
        if (_showWindowEvent is null)
        {
            return;
        }

        var handles =
            new WaitHandle[]
            {
                _showWindowEvent,
                _shutdownEvent
            };

        while (true)
        {
            var result =
                WaitHandle.WaitAny(
                    handles);

            if (result == 1)
            {
                return;
            }

            Dispatcher.BeginInvoke(
                ShowMainWindow);
        }
    }

    private void InitializeTrayIcon()
    {
        var menu =
            new Forms.ContextMenuStrip();

        var openItem =
            new Forms.ToolStripMenuItem(
                "Открыть SecurityGuard");

        openItem.Click +=
            (_, _) =>
                ShowMainWindow();

        var exitItem =
            new Forms.ToolStripMenuItem(
                "Выход");

        exitItem.Click +=
            (_, _) =>
                ExitApplication();

        menu.Items.Add(
            openItem);

        menu.Items.Add(
            new Forms.ToolStripSeparator());

        menu.Items.Add(
            exitItem);

        _trayIcon =
            new Forms.NotifyIcon
            {
                Icon =
                    SystemIcons.Shield,
                Text =
                    "SecurityGuard",
                Visible =
                    true,
                ContextMenuStrip =
                    menu
            };

        _trayIcon.DoubleClick +=
            (_, _) =>
                ShowMainWindow();
    }

    private void OnMainWindowClosing(
        object? sender,
        CancelEventArgs e)
    {
        if (_isExiting)
        {
            return;
        }

        e.Cancel =
            true;

        if (MainWindow is Window window)
        {
            window.Hide();
        }
    }

    private void ShowMainWindow()
    {
        if (MainWindow is not Window window)
        {
            return;
        }

        if (!window.IsVisible)
        {
            window.Show();
        }

        if (window.WindowState ==
            WindowState.Minimized)
        {
            window.WindowState =
                WindowState.Normal;
        }

        window.Activate();
        window.Topmost =
            true;
        window.Topmost =
            false;
        window.Focus();
    }

    private void ExitApplication()
    {
        _isExiting =
            true;

        if (_trayIcon is not null)
        {
            _trayIcon.Visible =
                false;

            _trayIcon.Dispose();
            _trayIcon =
                null;
        }

        if (MainWindow is Window window)
        {
            window.Close();
        }

        Shutdown();
    }

    protected override void OnExit(
        ExitEventArgs e)
    {
        _shutdownEvent.Set();

        if (_listenerThread is
            {
                IsAlive: true
            })
        {
            _listenerThread.Join(
                1000);
        }

        _showWindowEvent?.Dispose();
        _showWindowEvent =
            null;

        _shutdownEvent.Dispose();

        if (_ownsMutex &&
            _instanceMutex is not null)
        {
            try
            {
                _instanceMutex.ReleaseMutex();
            }
            catch (ApplicationException)
            {
            }
        }

        _instanceMutex?.Dispose();
        _instanceMutex =
            null;

        if (_trayIcon is not null)
        {
            _trayIcon.Visible =
                false;

            _trayIcon.Dispose();
            _trayIcon =
                null;
        }

        base.OnExit(
            e);
    }
}