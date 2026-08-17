using System.Windows.Input;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.UI.ViewModels;

public sealed class DecisionActionViewModel
{
    public SecurityAction Action { get; }

    public string DisplayName { get; }

    public ICommand Command { get; }

    public DecisionActionViewModel(
        SecurityAction action,
        Func<SecurityAction, Task> executeAsync)
    {
        Action = action;

        DisplayName =
            GetDisplayName(action);

        Command =
            new AsyncRelayCommand(
                () => executeAsync(action));
    }

    private static string GetDisplayName(
        SecurityAction action)
    {
        return action switch
        {
            SecurityAction.Allow =>
                "Разрешить всегда",

            SecurityAction.AllowOnce =>
                "Разрешить один раз",

            SecurityAction.Block =>
                "Заблокировать",

            SecurityAction.Quarantine =>
                "Карантин",

            SecurityAction.Delete =>
                "Удалить",

            _ =>
                action.ToString()
        };
    }
}