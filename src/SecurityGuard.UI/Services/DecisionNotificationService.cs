using System.Windows;
using SecurityGuard.UI.ViewModels;

namespace SecurityGuard.UI.Services;

public sealed class DecisionNotificationService
    : IDecisionNotificationService
{
    private readonly List<DecisionNotificationWindow> _windows =
        [];

    public void Show(
        DecisionRequestViewModel request)
    {
        if (_windows.Any(
                window =>
                    window.RequestId ==
                    request.Id))
        {
            return;
        }

        var window =
            new DecisionNotificationWindow(
                request);

        window.Closed +=
            WindowOnClosed;

        _windows.Add(
            window);

        window.Show();

        PositionWindows();
    }

    public void Dismiss(
        Guid requestId)
    {
        var window =
            _windows.FirstOrDefault(
                item =>
                    item.RequestId ==
                    requestId);

        if (window is null)
        {
            return;
        }

        _windows.Remove(
            window);

        window.Closed -=
            WindowOnClosed;

        window.Close();

        PositionWindows();
    }

    private void WindowOnClosed(
        object? sender,
        EventArgs e)
    {
        if (sender is not
            DecisionNotificationWindow window)
        {
            return;
        }

        _windows.Remove(
            window);

        window.Closed -=
            WindowOnClosed;

        PositionWindows();
    }

    private void PositionWindows()
    {
        var workArea =
            SystemParameters.WorkArea;

        var bottom =
            workArea.Bottom - 12;

        foreach (var window in
                 _windows.AsEnumerable().Reverse())
        {
            window.Left =
                workArea.Right -
                window.ActualWidth -
                12;

            window.Top =
                bottom -
                window.ActualHeight;

            bottom =
                window.Top - 8;
        }
    }
}