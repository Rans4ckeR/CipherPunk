﻿namespace CipherPunk;

public interface IWindowsCipherSuiteDocumentationService
{
    Dictionary<WindowsSchannelVersion, List<WindowsDocumentationCipherSuiteConfiguration>> GetWindowsDocumentationCipherSuiteConfigurations();

    List<WindowsDocumentationCipherSuiteConfiguration> GetWindowsDocumentationCipherSuiteConfigurations(WindowsSchannelVersion windowsSchannelVersion);
}