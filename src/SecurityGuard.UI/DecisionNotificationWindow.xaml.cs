using System.Windows;
using System.Windows.Controls;
using SecurityGuard.UI.ViewModels;

namespace SecurityGuard.UI;

public partial class DecisionNotificationWindow
    : Window
{
    public Guid RequestId { get; }

    public DecisionNotificationWindow(
        DecisionRequestViewModel request)
    {
        InitializeComponent();

        RequestId =
            request.Id;

        DataContext =
            request;
    }

    private void ActionButtonOnClick(
        object sender,
        RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button
            {
                DataContext:
                    DecisionActionViewModel action
            } &&
            action.Command.CanExecute(
                null))
        {
            action.Command.Execute(
                null);
        }

        Close();
    }

    private void DismissButtonOnClick(
        object sender,
        RoutedEventArgs e)
    {
        Close();
    }
}