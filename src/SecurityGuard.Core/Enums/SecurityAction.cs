namespace SecurityGuard.Core.Enums;

public enum SecurityAction
{
    None = 0,
    Allow = 1,
    AllowOnce = 2,
    Block = 3,
    Quarantine = 4,
    Delete = 5
}