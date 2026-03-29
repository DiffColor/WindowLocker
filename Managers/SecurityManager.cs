using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Windows;
using WindowLocker.Utilities;

namespace WindowLocker.Managers
{
    public static class SecurityManager
    {
        private const int DefaultProcessTimeoutMilliseconds = 30000;
        private const int BackgroundProcessStartupTimeoutMilliseconds = 2000;
        public const string DefaultSignageAutoLoginPassword = "1234";

        private const uint UserInfoLevel1 = 1;
        private const uint UserFlagPasswordNotRequired = 0x0020;
        private const int NetApiSuccess = 0;
        private const int NetApiUserNotFound = 2221;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct USER_INFO_1
        {
            public string usri1_name;
            public string usri1_password;
            public uint usri1_password_age;
            public uint usri1_priv;
            public string usri1_home_dir;
            public string usri1_comment;
            public uint usri1_flags;
            public string usri1_script_path;
        }

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetUserGetInfo(
            string servername,
            string username,
            uint level,
            out IntPtr bufptr);

        [DllImport("Netapi32.dll")]
        private static extern int NetApiBufferFree(IntPtr buffer);

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

        public static string ConfigureSignageAutoLogin(string username, string configuredPassword)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                throw new InvalidOperationException("Auto login username is required for signage settings.");
            }

            if (IsLocalUserPasswordMissing(username))
            {
                SetLocalUserPassword(username, DefaultSignageAutoLoginPassword);
                SetAutoLogin(true, username, DefaultSignageAutoLoginPassword);

                return DefaultSignageAutoLoginPassword;
            }

            SetAutoLogin(false);
            return null;
        }

        public static bool IsLocalUserPasswordMissing(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                return false;
            }

            return IsLocalUserPasswordNotRequired(username);
        }

        public static bool IsAutoLoginConfiguredForUser(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                return false;
            }

            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"))
            {
                if (key == null)
                {
                    return false;
                }

                string autoAdminLogon = key.GetValue("AutoAdminLogon") as string;
                string defaultUserName = key.GetValue("DefaultUserName") as string;

                return string.Equals(autoAdminLogon, "1", StringComparison.OrdinalIgnoreCase) &&
                       string.Equals(defaultUserName, username, StringComparison.OrdinalIgnoreCase);
            }
        }

        private static bool IsLocalUserPasswordNotRequired(string username)
        {
            IntPtr userInfoBuffer = IntPtr.Zero;

            try
            {
                int result = NetUserGetInfo(null, username, UserInfoLevel1, out userInfoBuffer);
                if (result == NetApiUserNotFound)
                {
                    return false;
                }

                if (result != NetApiSuccess)
                {
                    throw new Exception($"NetUserGetInfo failed with code {result}.");
                }

                USER_INFO_1 userInfo = (USER_INFO_1)Marshal.PtrToStructure(userInfoBuffer, typeof(USER_INFO_1));
                return (userInfo.usri1_flags & UserFlagPasswordNotRequired) == UserFlagPasswordNotRequired;
            }
            finally
            {
                if (userInfoBuffer != IntPtr.Zero)
                {
                    NetApiBufferFree(userInfoBuffer);
                }
            }
        }

        private static void SetLocalUserPassword(string username, string password)
        {
            try
            {
                RunProcess(
                    "net",
                    $"user \"{username}\" \"{password}\"",
                    DefaultProcessTimeoutMilliseconds,
                    "Local user password update");
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to set password for local user '{username}': {ex.Message}", ex);
            }
        }

        public static void SetSmartScreenEnabled(bool enabled)
        {
            try
            {
                SetWindowsShellSmartScreenPolicy(enabled);
                SetWindowsExplorerSmartScreenState(enabled);
                SetWindowsAppInstallControlPolicy(enabled);
                SetStoreAppsSmartScreenState(enabled);
                SetLegacyEdgeSmartScreenPolicy(enabled);
                SetChromiumEdgeSmartScreenPolicy(enabled);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error setting SmartScreen: {ex.Message}");
                throw;
            }
        }

        private static void SetWindowsShellSmartScreenPolicy(bool enabled)
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
        }

        private static void SetWindowsExplorerSmartScreenState(bool enabled)
        {
            using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", true))
            {
                key.SetValue("SmartScreenEnabled", enabled ? "Warn" : "Off", RegistryValueKind.String);
            }
        }

        private static void SetWindowsAppInstallControlPolicy(bool enabled)
        {
            using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen", true))
            {
                if (!enabled)
                {
                    key.SetValue("ConfigureAppInstallControlEnabled", 1, RegistryValueKind.DWord);
                    key.SetValue("ConfigureAppInstallControl", "Anywhere", RegistryValueKind.String);
                }
                else
                {
                    key.DeleteValue("ConfigureAppInstallControlEnabled", false);
                    key.DeleteValue("ConfigureAppInstallControl", false);
                }
            }
        }

        private static void SetStoreAppsSmartScreenState(bool enabled)
        {
            using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost", true))
            {
                key.SetValue("EnableWebContentEvaluation", enabled ? 1 : 0, RegistryValueKind.DWord);
            }
        }

        private static void SetLegacyEdgeSmartScreenPolicy(bool enabled)
        {
            using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter", true))
            {
                if (!enabled)
                {
                    key.SetValue("EnabledV9", 0, RegistryValueKind.DWord);
                    key.SetValue("PreventOverride", 0, RegistryValueKind.DWord);
                    key.SetValue("PreventOverrideAppRepUnknown", 0, RegistryValueKind.DWord);
                }
                else
                {
                    key.DeleteValue("EnabledV9", false);
                    key.DeleteValue("PreventOverride", false);
                    key.DeleteValue("PreventOverrideAppRepUnknown", false);
                }
            }
        }

        private static void SetChromiumEdgeSmartScreenPolicy(bool enabled)
        {
            using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Edge", true))
            {
                if (!enabled)
                {
                    key.SetValue("SmartScreenEnabled", 0, RegistryValueKind.DWord);
                    key.SetValue("SmartScreenPuaEnabled", 0, RegistryValueKind.DWord);
                }
                else
                {
                    key.DeleteValue("SmartScreenEnabled", false);
                    key.DeleteValue("SmartScreenPuaEnabled", false);
                }
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
                // `citool.exe -r` can keep running after the refresh request is accepted.
                // Waiting for full exit turns a successful request into a needless timeout.
                RunProcessUntilStartedOrExited(
                    "citool.exe",
                    "-r",
                    BackgroundProcessStartupTimeoutMilliseconds,
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

        private static void RunProcessUntilStartedOrExited(string fileName, string arguments, int startupTimeoutMilliseconds, string operationName)
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

                if (process.WaitForExit(startupTimeoutMilliseconds))
                {
                    if (process.ExitCode != 0)
                    {
                        throw new Exception($"{operationName} failed with exit code {process.ExitCode}");
                    }

                    return;
                }

                Debug.WriteLine($"{operationName} is still running after {startupTimeoutMilliseconds} ms. Continuing without waiting for exit.");
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
