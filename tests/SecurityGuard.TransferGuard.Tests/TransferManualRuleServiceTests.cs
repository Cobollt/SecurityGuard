[Fact]
public async Task Network_block_without_process_path_is_rejected()
{
    var service =
        CreateService();

    var request =
        new TransferManualRuleRequest(
            "Invalid block",
            TransferActivityKind.NetworkConnection,
            RuleDecision.Block,
            [
                new TransferManualRuleCondition(
                    RuleScope.RemoteAddress,
                    "1.1.1.1"),

                new TransferManualRuleCondition(
                    RuleScope.RemotePort,
                    "443"),

                new TransferManualRuleCondition(
                    RuleScope.Protocol,
                    "Tcp")
            ],
            200,
            null);

    await Assert.ThrowsAsync<InvalidOperationException>(
        () =>
            service.CreateAsync(
                request));
}

[Fact]
public async Task File_rule_requires_file_condition()
{
    var service =
        CreateService();

    var request =
        new TransferManualRuleRequest(
            "Invalid file rule",
            TransferActivityKind.FileTransfer,
            RuleDecision.Block,
            [
                new TransferManualRuleCondition(
                    RuleScope.Process,
                    "chrome.exe")
            ],
            250,
            null);

    await Assert.ThrowsAsync<InvalidOperationException>(
        () =>
            service.CreateAsync(
                request));
}