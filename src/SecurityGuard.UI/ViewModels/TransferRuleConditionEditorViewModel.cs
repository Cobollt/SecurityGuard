using System.ComponentModel;
using System.Runtime.CompilerServices;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.UI.ViewModels;

public sealed class TransferRuleConditionEditorViewModel
    : INotifyPropertyChanged
{
    private RuleScope _scope;

    private string _value =
        string.Empty;

    private IReadOnlyList<RuleScope> _availableScopes =
        [];

    public TransferRuleConditionEditorViewModel(
        IReadOnlyList<RuleScope> availableScopes)
    {
        SetAvailableScopes(
            availableScopes);
    }

    public IReadOnlyList<RuleScope> AvailableScopes =>
        _availableScopes;

    public RuleScope Scope
    {
        get => _scope;

        set
        {
            if (_scope ==
                value)
            {
                return;
            }

            _scope =
                value;

            OnPropertyChanged();
        }
    }

    public string Value
    {
        get => _value;

        set
        {
            if (_value ==
                value)
            {
                return;
            }

            _value =
                value;

            OnPropertyChanged();
        }
    }

    public void SetAvailableScopes(
        IReadOnlyList<RuleScope> scopes)
    {
        _availableScopes =
            scopes;

        OnPropertyChanged(
            nameof(
                AvailableScopes));

        if (scopes.Count == 0)
        {
            return;
        }

        if (!scopes.Contains(
                Scope))
        {
            Scope =
                scopes[0];
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged(
        [CallerMemberName]
        string? propertyName = null)
    {
        PropertyChanged?.Invoke(
            this,
            new PropertyChangedEventArgs(
                propertyName));
    }
}