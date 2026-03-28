using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Principal;
using System.Threading;
using System.Windows;
using WindowLocker.Utilities;

namespace WindowLocker.Managers
{
    public static class SecurityManager
    {
        private const int DefaultProcessTimeoutMilliseconds = 30000;

        /// <summary>
        /// Enables or disables the Registry Editor
        /// </summary>
        public static void SetRegistryEditorEnabled(bool enabled)
        {
            RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\System", true);

            if (key == null)
            {
                Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\System");
                key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\System", true);
            }

            try
            {
                if (!enabled)
                {
                    key.SetValue("DisableRegistryTools", 1, RegistryValueKind.DWord);
                }
                else
                {
                    key.DeleteValue("DisableRegistryTools", false);
                }
            }
            finally
            {
                key?.Close();
            }
        }

        /// <summary>
        /// Enables or disables the Command Prompt
        /// </summary>
        public static void SetCommandPromptEnabled(bool enabled)
        {
            RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Policies\Microsoft\Windows\System", true);

            if (key == null)
            {
                Registry.CurrentUser.CreateSubKey(@"Software\Policies\Microsoft\Windows\System");
                key = Registry.CurrentUser.OpenSubKey(@"Software\Policies\Microsoft\Windows\System", true);
            }

            try
            {
                if (!enabled)
                {
                    key.SetValue("DisableCMD", 1, RegistryValueKind.DWord);
                }
                else
                {
                    key.DeleteValue("DisableCMD", false);
                }
            }
            finally
            {
                key?.Close();
            }
        }

        /// <summary>
        /// Enables or disables PowerShell
        /// </summary>
        public static void SetPowerShellEnabled(bool enabled)
        {
            RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Policies\Microsoft\Windows\PowerShell", true);

            if (key == null)
            {
                Registry.CurrentUser.CreateSubKey(@"Software\Policies\Microsoft\Windows\PowerShell");
                key = Registry.CurrentUser.OpenSubKey(@"Software\Policies\Microsoft\Windows\PowerShell", true);
            }

            try
            {
                if (!enabled)
                {
                    key.SetValue("EnableScripts", 0, RegistryValueKind.DWord);
                    key.SetValue("ExecutionPolicy", "Disabled", RegistryValueKind.String);
                }
                else
                {
                    key.DeleteValue("EnableScripts", false);
                    key.DeleteValue("ExecutionPolicy", false);
                }
            }
            finally
            {
                key?.Close();
            }

            // Also disable PowerShell through CMD if needed
            SetCommandPromptEnabled(enabled);
        }

        /// <summary>
        /// Enables or disables the Administrator account
        /// </summary>
        public static void SetAdministratorAccountEnabled(bool enabled)
        {
            try
            {
                RunProcess(
                    "net",
                    $"user Administrator /active:{(enabled ? "yes" : "no")}",
                    DefaultProcessTimeoutMilliseconds,
                    "Administrator account state update");
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to set Administrator account state: {ex.Message}", ex);
            }
        }

        private static void CleanupAutologonTool(string path)
        {
            try
            {
                if (File.Exists(path))
                    File.Delete(path);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Failed to cleanup Autologon tool: {ex.Message}");
            }
        }

        public static void SetAutoLogin(bool enabled, string username = "", string password = "")
        {
            string fileName = "Autologon.exe";
            string resourceFullName = $"WindowLocker.Resources.{fileName}"; // 네임스페이스 포함 전체 경로
            string exePath = Path.Combine(Path.GetTempPath(), fileName);

            try
            {
                SystemUtilities.ExtractResourceToFile(resourceFullName, exePath);
                
                if (enabled && !string.IsNullOrEmpty(username))
                {
                    // 자동 로그인 활성화
                    RunProcess(
                        exePath,
                        $"/accepteula \"{username}\" \"\" \"{password}\"",
                        DefaultProcessTimeoutMilliseconds,
                        "Auto login enable");
                }
                else
                {
                    // 자동 로그인 비활성화
                    RunProcess(
                        exePath,
                        "/accepteula /disable",
                        DefaultProcessTimeoutMilliseconds,
                        "Auto login disable");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error setting auto login: {ex.Message}");
                throw;
            }
            finally
            {
                Thread.Sleep(120);

                if (exePath != null)
                {
                    CleanupAutologonTool(exePath);
                }
            }
        }

        public static void SetSmartScreenEnabled(bool enabled)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows\System", true))
                {
                    if (!enabled)
                    {
                        key.SetValue("EnableSmartScreen", 0, RegistryValueKind.DWord);
                    }
                    else
                    {
                        key.DeleteValue("EnableSmartScreen", false);
                    }
                }

                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", true))
                {
                    if (!enabled)
                    {
                        key.SetValue("SmartScreenEnabled", "Off", RegistryValueKind.String);
                    }
                    else
                    {
                        key.SetValue("SmartScreenEnabled", "On", RegistryValueKind.String);
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error setting SmartScreen: {ex.Message}");
                throw;
            }
        }

        public static void SetSmartAppControlEnabled(bool enabled)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Control\CI\Policy", true))
                {
                    if (key == null)
                    {
                        throw new Exception("Failed to open Smart App Control policy registry key");
                    }

                    if (!enabled)
                    {
                        key.SetValue("VerifiedAndReputablePolicyState", 0, RegistryValueKind.DWord);
                    }
                    else
                    {
                        key.DeleteValue("VerifiedAndReputablePolicyState", false);
                    }
                }

                RefreshCodeIntegrityPolicy();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error setting Smart App Control: {ex.Message}");
                throw;
            }
        }

        private static void RefreshCodeIntegrityPolicy()
        {
            try
            {
                RunProcess(
                    "citool.exe",
                    "-r",
                    DefaultProcessTimeoutMilliseconds,
                    "Code integrity policy refresh");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Failed to refresh code integrity policy: {ex.Message}");
                throw;
            }
        }

        private static void RunProcess(string fileName, string arguments, int timeoutMilliseconds, string operationName)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (Process process = new Process { StartInfo = startInfo })
            {
                if (!process.Start())
                {
                    throw new Exception($"{operationName} process failed to start");
                }

                if (!process.WaitForExit(timeoutMilliseconds))
                {
                    try
                    {
                        process.Kill();
                        process.WaitForExit(5000);
                    }
                    catch (Exception killEx)
                    {
                        Debug.WriteLine($"Failed to stop timed out process for {operationName}: {killEx.Message}");
                    }

                    throw new TimeoutException($"{operationName} timed out after {timeoutMilliseconds / 1000} seconds");
                }

                if (process.ExitCode != 0)
                {
                    throw new Exception($"{operationName} failed with exit code {process.ExitCode}");
                }
            }
        }

        public static void SetUACEnabled(bool enabled)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", true))
                {
                    if (!enabled)
                    {
                        // UAC 완전 비활성화
                        key.SetValue("EnableLUA", 0, RegistryValueKind.DWord);
                        key.SetValue("ConsentPromptBehaviorAdmin", 0, RegistryValueKind.DWord);
                        key.SetValue("PromptOnSecureDesktop", 0, RegistryValueKind.DWord);
                    }
                    else
                    {
                        // UAC 기본 설정으로 복원
                        key.SetValue("EnableLUA", 1, RegistryValueKind.DWord);
                        key.SetValue("ConsentPromptBehaviorAdmin", 5, RegistryValueKind.DWord);
                        key.SetValue("PromptOnSecureDesktop", 1, RegistryValueKind.DWord);
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error setting UAC: {ex.Message}");
                throw;
            }
        }
    }
}
