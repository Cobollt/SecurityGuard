using SecurityGuard.UI.ViewModels;

namespace SecurityGuard.UI.Services;

public interface IDecisionNotificationService
{
    void Show(
        DecisionRequestViewModel request);

    void Dismiss(
        Guid requestId);
}