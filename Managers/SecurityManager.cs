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
                // Administrator 계정 활성화/비활성화
                Process process = new Process();
                process.StartInfo.FileName = "net";
                process.StartInfo.Arguments = $"user Administrator /active:{(enabled ? "yes" : "no")}";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;
                process.StartInfo.Verb = "runas"; // 관리자 권한으로 실행

                process.Start();
                process.WaitForExit();

                if (process.ExitCode != 0)
                {
                    throw new Exception("Failed to modify Administrator account status");
                }
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
                    ProcessStartInfo startInfo = new ProcessStartInfo
                    {
                        FileName = exePath,
                        Arguments = $"/accepteula \"{username}\" \"\" \"{password}\"",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };
                    
                    using (Process process = Process.Start(startInfo))
                    {
                        process.WaitForExit();
                    }
                }
                else
                {
                    // 자동 로그인 비활성화
                    ProcessStartInfo startInfo = new ProcessStartInfo
                    {
                        FileName = exePath,
                        Arguments = "/accepteula /disable",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };
                    
                    using (Process process = Process.Start(startInfo))
                    {
                        process.WaitForExit();
                    }
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
                ProcessStartInfo startInfo = new ProcessStartInfo
                {
                    FileName = "citool.exe",
                    Arguments = "-r",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (Process process = Process.Start(startInfo))
                {
                    process.WaitForExit();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Failed to refresh code integrity policy: {ex.Message}");
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
