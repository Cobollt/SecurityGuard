[Fact]
public async Task Only_expired_rules_are_removed()
{
    var now =
        DateTimeOffset.UtcNow;

    var expired =
        CreateRule(
            now -
            TimeSpan.FromMinutes(1));

    var active =
        CreateRule(
            now +
            TimeSpan.FromMinutes(10));

    var repository =
        new FakeRuleRepository(
            [
                expired,
                active
            ]);

    var management =
        new RecordingRuleManagementService();

    var service =
        new SecurityRuleExpirationService(
            repository,
            management,
            new FakeAuditService());

    var removed =
        await service.RemoveExpiredAsync(
            now);

    Assert.Equal(
        1,
        removed);

    Assert.Contains(
        expired.Id,
        management.DeletedRuleIds);

    Assert.DoesNotContain(
        active.Id,
        management.DeletedRuleIds);
}