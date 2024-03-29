﻿namespace CipherPunk.UI;

using CipherPunk.CipherSuiteInfoApi;

internal sealed class CipherSuitesOsSettingsViewModel(ILogger logger, ICipherSuiteService cipherSuiteService, IUacService uacService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
    : BaseCipherSuitesSettingsViewModel(logger, cipherSuiteService, uacService, cipherSuiteInfoApiService)
{
    public string? AdminMessage => Elevated ? null : "Run as Administrator to modify the OS settings.";

    protected override IEnumerable<WindowsApiCipherSuiteConfiguration> GetActiveSettingConfiguration() => CipherSuiteService.GetOperatingSystemConfiguredCipherSuiteList();

    protected override void DoExecuteSaveSettingsCommand() => CipherSuiteService.UpdateCipherSuiteOrder(ModifiedSettingConfigurations!.Select(q => q.Id).ToArray());

    protected override void DoExecuteResetSettingsCommand() => CipherSuiteService.ResetCipherSuiteListToOperatingSystemDefault();
}