namespace CipherPunk.UI;

using CipherPunk.CipherSuiteInfoApi;

internal sealed class CipherSuitesGroupPolicySettingsViewModel(
    ILogger logger,
    ICipherSuiteService cipherSuiteService,
    IUacIconService uacIconService,
    ICipherSuiteInfoApiService cipherSuiteInfoApiService,
    IGroupPolicyService groupPolicyService)
    : BaseCipherSuitesSettingsViewModel(logger, cipherSuiteService, uacIconService, cipherSuiteInfoApiService)
{
    private string? adminMessage;

    public string? AdminMessage
    {
        get => adminMessage;
        private set => _ = SetProperty(ref adminMessage, value);
    }

    protected override IEnumerable<WindowsApiCipherSuiteConfiguration> GetActiveCipherSuiteConfiguration()
    {
        string[] windowsActiveGroupPolicyCipherSuiteConfigurationsStrings = [];

        AdminMessage = null;

        try
        {
            windowsActiveGroupPolicyCipherSuiteConfigurationsStrings = groupPolicyService.GetSslCipherSuiteOrderPolicy();
        }
        catch (UnauthorizedAccessException)
        {
            AdminMessage = "Run as Administrator to view and modify the Group Policy settings.";
        }

        return CipherSuiteService.GetOperatingSystemActiveCipherSuiteList().Where(q => windowsActiveGroupPolicyCipherSuiteConfigurationsStrings.Contains(q.CipherSuite.ToString(), StringComparer.OrdinalIgnoreCase));
    }

    protected override void DoExecuteSaveCipherSuitesCommand() => groupPolicyService.UpdateSslCipherSuiteOrderPolicy(ModifiedCipherSuiteConfigurations!.Select(q => q.Id.ToString()).ToArray());

    protected override void DoExecuteResetCipherSuitesCommand() => groupPolicyService.UpdateSslCipherSuiteOrderPolicy([]);

    protected override bool CanExecuteAddCipherSuiteCommand(UiWindowsDocumentationCipherSuiteConfiguration? uiWindowsDocumentationCipherSuiteConfiguration)
        => string.IsNullOrWhiteSpace(AdminMessage) && base.CanExecuteAddCipherSuiteCommand(uiWindowsDocumentationCipherSuiteConfiguration);

    protected override bool CanExecuteCancelCipherSuitesCommand()
        => string.IsNullOrWhiteSpace(AdminMessage) && base.CanExecuteCancelCipherSuitesCommand();

    protected override bool CanExecuteDeleteCipherSuiteCommand(UiWindowsApiCipherSuiteConfiguration? uiWindowsApiCipherSuiteConfiguration)
        => string.IsNullOrWhiteSpace(AdminMessage) && base.CanExecuteDeleteCipherSuiteCommand(uiWindowsApiCipherSuiteConfiguration);

    protected override bool CanExecuteMoveCipherSuiteUpCommand(UiWindowsApiCipherSuiteConfiguration? uiWindowsApiCipherSuiteConfiguration)
        => string.IsNullOrWhiteSpace(AdminMessage) && base.CanExecuteMoveCipherSuiteUpCommand(uiWindowsApiCipherSuiteConfiguration);

    protected override bool CanExecuteMoveCipherSuiteDownCommand(UiWindowsApiCipherSuiteConfiguration? uiWindowsApiCipherSuiteConfiguration)
        => string.IsNullOrWhiteSpace(AdminMessage) && base.CanExecuteMoveCipherSuiteDownCommand(uiWindowsApiCipherSuiteConfiguration);

    protected override bool CanExecuteResetCipherSuitesCommand()
        => string.IsNullOrWhiteSpace(AdminMessage) && base.CanExecuteResetCipherSuitesCommand();

    protected override bool CanExecuteSaveCipherSuitesCommand()
        => string.IsNullOrWhiteSpace(AdminMessage) && base.CanExecuteSaveCipherSuitesCommand();
}