using System.Collections.ObjectModel;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.UI.ViewModels;

public sealed class DecisionRequestViewModel
{
    public Guid Id { get; }

    public SecurityModuleKind ModuleKind { get; }

    public string Module =>
        ModuleKind.ToString();

    public string Title { get; }

    public string Description { get; }

    public string? FilePath { get; }

    public string? ProcessName { get; }

    public DateTimeOffset CreatedAtUtc { get; }

    public ObservableCollection<DecisionActionViewModel> Actions { get; }

    public DecisionRequestViewModel(
        SecurityDecisionRequest request,
        Func<Guid, SecurityAction, Task> submitAsync)
    {
        Id =
            request.Id;

        ModuleKind =
            request.Module;

        Title =
            request.Title;

        Description =
            request.Description;

        FilePath =
            request.FilePath;

        ProcessName =
            request.ProcessName;

        CreatedAtUtc =
            request.CreatedAtUtc;

        Actions =
            new ObservableCollection<DecisionActionViewModel>(
                request.AvailableActions.Select(
                    action =>
                        new DecisionActionViewModel(
                            action,
                            selectedAction =>
                                submitAsync(
                                    request.Id,
                                    selectedAction))));
    }
}
