using SecurityGuard.UI.Services;
using SecurityGuard.UI.ViewModels;

namespace SecurityGuard.UI.Tests;

internal sealed class FakeDecisionNotificationService
    : IDecisionNotificationService
{
    public List<Guid> ShownRequestIds { get; } =
        [];

    public List<Guid> DismissedRequestIds { get; } =
        [];

    public void Show(
        DecisionRequestViewModel request)
    {
        ShownRequestIds.Add(
            request.Id);
    }

    public void Dismiss(
        Guid requestId)
    {
        DismissedRequestIds.Add(
            requestId);
    }
}