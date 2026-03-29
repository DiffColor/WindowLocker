using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Threading;
using System.Timers;
using Microsoft.Win32;
using TurtleTools;
using WindowLocker.Utilities;
using Timer = System.Timers.Timer;

namespace WindowLocker.Managers
{
    public static class SystemManager
    {
        private static Timer _taskbarCheckTimer;
        private const int SignageLogPixels = 96;
        
        public static void SetTaskbarEnabled(bool enabled)
        {
            try
            {
                // Windows 키 후킹 설정
                KeyboardHookManager.WinBlocked = !enabled;

                // 작업표시줄 표시/숨김 설정
                if (!enabled)
                {
                    Taskbar.Hide();
                    
                    // 작업표시줄 모니터링 타이머 시작
                    if (_taskbarCheckTimer == null)
                    {
                        _taskbarCheckTimer = new Timer();
                        _taskbarCheckTimer.Interval = 1000; // 1초마다 체크
                        _taskbarCheckTimer.Elapsed += (s, e) =>
                        {
                            if (Taskbar.IsTaskbarVisible())
                            {
                                Taskbar.Hide();
                            }
                        };
                    }
                    _taskbarCheckTimer.Start();
                }
                else
                {
                    _taskbarCheckTimer?.Stop();
                    Taskbar.Show();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error in SetTaskbarEnabled: {ex.Message}");
            }
        }

        /// <summary>
        /// Enables or disables the Settings App
        /// </summary>
        public static void SetSettingsAppEnabled(bool enabled)
        {
            RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", true);

            if (key == null)
            {
                Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer");
                key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", true);
            }

            try
            {
                if (!enabled)
                {
                    key.SetValue("NoControlPanel", 1, RegistryValueKind.DWord);
                }
                else
                {
                    key.DeleteValue("NoControlPanel", false);
                }
            }
            finally
            {
                key?.Close();
            }
        }

        /// <summary>
        /// Enables or disables the Task Manager
        /// </summary>
        public static void SetTaskManagerEnabled(bool enabled)
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
                    key.SetValue("DisableTaskMgr", 1, RegistryValueKind.DWord);
                }
                else
                {
                    key.DeleteValue("DisableTaskMgr", false);
                }
            }
            finally
            {
                key?.Close();
            }
        }

        private static void BlockExecutable(string executableName)
        {
            try
            {
                string[] commonPaths = {
                    @"C:\Windows\System32",
                    @"C:\Windows\SysWOW64",
                    @"C:\Windows\WinSxS",
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
                };

                foreach (string basePath in commonPaths)
                {
                    string execPath = Path.Combine(basePath, executableName);
                    if (File.Exists(execPath))
                    {
                        FileInfo fileInfo = new FileInfo(execPath);
                        FileSecurity fileSecurity = fileInfo.GetAccessControl();
                        fileSecurity.SetAccessRuleProtection(true, false);

                        SecurityIdentifier everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
                        SecurityIdentifier users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);

                        fileSecurity.RemoveAccessRuleAll(new FileSystemAccessRule(everyone, FileSystemRights.FullControl, AccessControlType.Allow));
                        fileSecurity.RemoveAccessRuleAll(new FileSystemAccessRule(users, FileSystemRights.FullControl, AccessControlType.Allow));

                        fileInfo.SetAccessControl(fileSecurity);
                        fileInfo.Attributes = FileAttributes.Hidden | FileAttributes.System;
                    }
                }
            }
            catch { }
        }

        public static void SetCommandPromptEnabled(bool enabled)
        {
            try
            {
                // HKLM 시스템 정책 설정
                RegistryKey systemKey = null;
                try
                {
                    systemKey = Registry.LocalMachine.CreateSubKey(@"Software\Policies\Microsoft\Windows\System", true);
                    if (!enabled)
                    {
                        systemKey.SetValue("DisableCMD", 2, RegistryValueKind.DWord);
                    }
                    else
                    {
                        systemKey.DeleteValue("DisableCMD", false);
                    }
                }
                finally
                {
                    systemKey?.Close();
                }

                // HKCU 시스템 정책 설정
                RegistryKey userKey = null;
                try
                {
                    userKey = Registry.CurrentUser.CreateSubKey(@"Software\Policies\Microsoft\Windows\System", true);
                    if (!enabled)
                    {
                        userKey.SetValue("DisableCMD", 2, RegistryValueKind.DWord);
                    }
                    else
                    {
                        userKey.DeleteValue("DisableCMD", false);
                    }
                }
                finally
                {
                    userKey?.Close();
                }

                // DisallowRun 설정
                RegistryKey explorerKey = null;
                try
                {
                    explorerKey = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", true);
                    if (!enabled)
                    {
                        explorerKey.SetValue("DisallowRun", 1, RegistryValueKind.DWord);

                        using (RegistryKey disallowKey = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun", true))
                        {
                            disallowKey.SetValue("1", "cmd.exe", RegistryValueKind.String);
                            disallowKey.SetValue("2", "command.com", RegistryValueKind.String);
                        }
                    }
                    else
                    {
                        explorerKey.DeleteValue("DisallowRun", false);
                        Registry.CurrentUser.DeleteSubKeyTree(@"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun", false);
                    }
                }
                finally
                {
                    explorerKey?.Close();
                }

                // PowerShell 차단/해제
                SetPowerShellEnabled(enabled);
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to set Command Prompt state: {ex.Message}", ex);
            }
        }

        public static void SetPowerShellEnabled(bool enabled)
        {
            try
            {
                // 기존 코드 유지...

                // 추가: Image File Execution Options를 통한 차단
                if (!enabled)
                {
                    string[] psExecutables = {
                        "powershell.exe", "powershell_ise.exe", "pwsh.exe",
                        "PowerShell_ISE.exe", "powershell6.exe", "powershell7.exe"
                    };

                    foreach (string exe in psExecutables)
                    {
                        using (RegistryKey ifeoKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", true))
                        {
                            if (ifeoKey != null)
                            {
                                // 실행 파일별 키 생성
                                RegistryKey exeKey = ifeoKey.OpenSubKey(exe, true);
                                if (exeKey == null)
                                {
                                    exeKey = ifeoKey.CreateSubKey(exe);
                                }
                                else
                                {
                                    exeKey.Close();
                                    exeKey = ifeoKey.OpenSubKey(exe, true);
                                }

                                // 디버거 값을 설정하여 실행 차단
                                exeKey.SetValue("Debugger", "block.exe", RegistryValueKind.String);
                                exeKey.Close();
                            }
                        }
                    }
                }
                else
                {
                    // 차단 해제 시 Image File Execution Options 제거
                    string[] psExecutables = {
                        "powershell.exe", "powershell_ise.exe", "pwsh.exe",
                        "PowerShell_ISE.exe", "powershell6.exe", "powershell7.exe"
                    };

                    foreach (string exe in psExecutables)
                    {
                        try
                        {
                            using (RegistryKey ifeoKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", true))
                            {
                                if (ifeoKey != null)
                                {
                                    ifeoKey.DeleteSubKeyTree(exe, false);
                                }
                            }
                        }
                        catch { }
                    }
                }

                // 추가: 파일 권한 제거
                if (!enabled)
                {
                    string[] psExecutables = {
                        "powershell.exe", "powershell_ise.exe", "pwsh.exe",
                        "PowerShell_ISE.exe", "powershell6.exe", "powershell7.exe"
                    };

                    foreach (string exe in psExecutables)
                    {
                        BlockExecutable(exe);
                    }
                }

                // 추가: PowerShell 모듈 폴더 접근 제한
                //    if (!enabled)
                //    {
                //        string[] psFolders = {
                //            @"C:\Windows\System32\WindowsPowerShell",
                //            @"C:\Windows\SysWOW64\WindowsPowerShell",
                //            @"C:\Program Files\PowerShell",
                //            @"C:\Program Files\WindowsPowerShell"
                //        };

                //        foreach (string folder in psFolders)
                //        {
                //            try
                //            {
                //                if (Directory.Exists(folder))
                //                {
                //                    DirectoryInfo dirInfo = new DirectoryInfo(folder);
                //                    DirectorySecurity dirSecurity = dirInfo.GetAccessControl();
                //                    dirSecurity.SetAccessRuleProtection(true, false);

                //                    SecurityIdentifier everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
                //                    SecurityIdentifier users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);

                //                    dirSecurity.RemoveAccessRuleAll(new FileSystemAccessRule(everyone, FileSystemRights.FullControl, AccessControlType.Allow));
                //                    dirSecurity.RemoveAccessRuleAll(new FileSystemAccessRule(users, FileSystemRights.FullControl, AccessControlType.Allow));

                //                    dirInfo.SetAccessControl(dirSecurity);
                //                }
                //            }
                //            catch { }
                //        }
                //    }
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to set PowerShell state: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Enables or disables Remote Desktop
        /// </summary>
        public static void SetRemoteDesktopEnabled(bool enabled)
        {
            RegistryKey key = null;
            try
            {
                key = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server", true);
                if (!enabled)
                {
                    key.SetValue("fDenyTSConnections", 1, RegistryValueKind.DWord);
                }
                else
                {
                    key.SetValue("fDenyTSConnections", 0, RegistryValueKind.DWord);
                }
            }
            finally
            {
                key?.Close();
            }
        }

        /// <summary>
        /// Enables or disables Hardware Acceleration
        /// </summary>
        public static void SetHardwareAccelerationEnabled(bool enabled)
        {
            RegistryKey key = null;
            try
            {
                key = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Microsoft\Avalon.Graphics", true);
                if (!enabled)
                {
                    key.SetValue("DisableHWAcceleration", 1, RegistryValueKind.DWord);
                }
                else
                {
                    key.DeleteValue("DisableHWAcceleration", false);
                }
            }
            finally
            {
                key?.Close();
            }
        }

        /// <summary>
        /// Apply default signage settings (kiosk mode settings)
        /// </summary>
        public static void ApplySignageSettings()
        {
            try
            {
                // Lock Screen Settings
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows\Personalization", true))
                {
                    key.SetValue("NoLockScreen", 1, RegistryValueKind.DWord);
                }

                // Screen Saver Settings
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop", true))
                {
                    key.SetValue("ScreenSaveActive", "0", RegistryValueKind.String);
                    key.SetValue("SCRNSAVE.EXE", "", RegistryValueKind.String);
                    key.SetValue("ScreenSaverIsSecure", "0", RegistryValueKind.String);
                }

                // Power Settings
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Control\Power", true))
                {
                    key.SetValue("CsEnabled", 0, RegistryValueKind.DWord);
                }

                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Power", true))
                {
                    key.SetValue("HiberbootEnabled", 0, RegistryValueKind.DWord);
                    key.SetValue("AwayModeEnabled", 1, RegistryValueKind.DWord);
                }

                ApplySignageDesktopScaling();

                // 주모니터에만 작업표시줄 표시 설정
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3", true))
                {
                    if (key != null)
                    {
                        // StuckRects3 키의 바이너리 데이터를 읽어옴
                        byte[] settings = key.GetValue("Settings") as byte[];
                        
                        if (settings != null && settings.Length >= 44)
                        {
                            // 9번째 바이트에 작업표시줄 설정 값이 있음
                            // 첫 번째 비트가 1이면 '다른 디스플레이에도 작업 표시줄 단추 표시'가 활성화됨
                            // 첫 번째 비트를 0으로 설정하여 주모니터에만 작업표시줄 표시
                            settings[8] &= 0xFE; // 첫 번째 비트를 0으로 설정 (AND 연산 0xFE = 11111110)
                            
                            // 수정된 값 저장
                            key.SetValue("Settings", settings, RegistryValueKind.Binary);
                        }
                    }
                }

                // MMTaskbar 설정 - 주 모니터에만 작업표시줄 표시
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced", true))
                {
                    key.SetValue("MMTaskbarEnabled", 0, RegistryValueKind.DWord);
                }

                // 세 손가락, 네 손가락 제스처 비활성화 설정
                // 1. Microsoft Precision TouchPad 제스처 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\PrecisionTouchPad", true))
                {
                    // 세 손가락 제스처 비활성화
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("ThreeFingerSlideEnabled", 0, RegistryValueKind.DWord);
                    key.SetValue("ThreeFingerTapEnabled", 0, RegistryValueKind.DWord);
                    
                    // 네 손가락 제스처 비활성화
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerSlideEnabled", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerTapEnabled", 0, RegistryValueKind.DWord);
                    
                    // 추가 제스처 설정
                    key.SetValue("EnableMultiTap", 1, RegistryValueKind.DWord);
                    key.SetValue("EnableSwipeGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("AAPolicy", 0, RegistryValueKind.DWord);
                }

                // 2. 터치 활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Wisp\Touch", true))
                {
                    key.SetValue("TouchGate", 1, RegistryValueKind.DWord);
                }

                // 3. 엣지 제스처 및 윈도우 제스처 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\ImmersiveShell", true))
                {
                    key.SetValue("EdgeUiDisabled", 1, RegistryValueKind.DWord);
                }

                // 4. 시스템 수준의 터치 제스처 비활성화
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows\EdgeUI", true))
                {
                    key.SetValue("DisableTouchTabletMode", 1, RegistryValueKind.DWord);
                }

                // 5. 터치스크린 제스처 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Control Panel\Desktop", true))
                {
                    key.SetValue("TouchGesture", 0, RegistryValueKind.DWord);
                    key.SetValue("TouchGestureSetting", 0, RegistryValueKind.DWord);
                }

                // 6. Synaptics 터치패드 설정 비활성화 (널리 사용되는 터치패드)
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Synaptics\SynTP\TouchPadPS2", true))
                {
                    key.SetValue("3FingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("4FingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("GestureMode", 0, RegistryValueKind.DWord);
                }

                // 7. Synaptics 추가 설정
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Synaptics\SynTPEnh", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("GestureMode", 0, RegistryValueKind.DWord);
                }

                // 8. ELAN 터치패드 설정 비활성화 (널리 사용되는 다른 터치패드)
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Elantech\SmartPad", true))
                {
                    key.SetValue("Gesture_3F_Enable", 0, RegistryValueKind.DWord);
                    key.SetValue("Gesture_4F_Enable", 0, RegistryValueKind.DWord);
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                }

                // 9. ALPS 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Alps\Apoint", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("GestureMode", 0, RegistryValueKind.DWord);
                }

                // 10. Cirque 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Cirque\GlidePoint", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("AdvancedGestures", 0, RegistryValueKind.DWord);
                }

                // 11. FocalTech 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\FocalTech\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("GestureEnable", 0, RegistryValueKind.DWord);
                }

                // 12. Goodix 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Goodix\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("GestureMode", 0, RegistryValueKind.DWord);
                }

                // 13. Weida 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Weida\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("GestureEnable", 0, RegistryValueKind.DWord);
                }

                // 14. Sentelic 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Sentelic\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("GestureMode", 0, RegistryValueKind.DWord);
                }

                // 15. Atmel 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Atmel\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                }

                // 16. Validity 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Validity\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("GestureEnable", 0, RegistryValueKind.DWord);
                }

                // 17. Wacom 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Wacom\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("GestureMode", 0, RegistryValueKind.DWord);
                }

                // 18. Realtek 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Realtek\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                }

                // 19. Broadcom 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Broadcom\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("GestureEnable", 0, RegistryValueKind.DWord);
                }

                // 20. Cypress 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Cypress\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                }

                // 21. Ilitek 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Ilitek\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("GestureMode", 0, RegistryValueKind.DWord);
                }

                // 22. Pixart 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Pixart\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("GestureEnable", 0, RegistryValueKind.DWord);
                }

                // 23. Novatek 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Novatek\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                }

                // 24. Himax 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Himax\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("GestureMode", 0, RegistryValueKind.DWord);
                }

                // 25. Raydium 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Raydium\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("GestureEnable", 0, RegistryValueKind.DWord);
                }

                // 26. Melfas 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Melfas\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                }

                // 27. Silead 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Silead\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("GestureMode", 0, RegistryValueKind.DWord);
                }

                // 28. Chipone 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Chipone\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("GestureEnable", 0, RegistryValueKind.DWord);
                }

                // 29. 일반적인 HID 터치패드 설정 활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Input\TIPC", true))
                {
                    key.SetValue("Enabled", 1, RegistryValueKind.DWord);
                }

                // 30. Windows 10/11 터치 키보드 및 필기판 서비스 비활성화
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\TabletTip\1.7", true))
                {
                    key.SetValue("EnableAutocorrection", 0, RegistryValueKind.DWord);
                    key.SetValue("EnableSpellchecking", 0, RegistryValueKind.DWord);
                    key.SetValue("EnableTextPrediction", 0, RegistryValueKind.DWord);
                    key.SetValue("EnableDoubleTapSpace", 0, RegistryValueKind.DWord);
                }

                // 31. 추가 Windows 제스처 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", true))
                {
                    key.SetValue("EnableBalloonTips", 0, RegistryValueKind.DWord);
                    key.SetValue("DisablePreviewDesktop", 1, RegistryValueKind.DWord);
                }

                // 32. Windows Ink 워크스페이스 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\PenWorkspace", true))
                {
                    key.SetValue("PenWorkspaceAppSuggestionsEnabled", 0, RegistryValueKind.DWord);
                }

                // 33. 터치 키보드 자동 호출 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\TabletTip\1.7", true))
                {
                    key.SetValue("TipbandDesiredVisibility", 0, RegistryValueKind.DWord);
                }

                // 34. Intel 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Intel\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("GestureMode", 0, RegistryValueKind.DWord);
                }

                // 35. AMD 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\AMD\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                }

                // 36. Qualcomm 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Qualcomm\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("GestureEnable", 0, RegistryValueKind.DWord);
                }

                // 37. Mediatek 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Mediatek\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("GestureMode", 0, RegistryValueKind.DWord);
                }

                // 38. Samsung 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Samsung\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                }

                // 39. LG 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\LG\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("GestureEnable", 0, RegistryValueKind.DWord);
                }

                // 40. Dell 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Dell\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("GestureMode", 0, RegistryValueKind.DWord);
                }

                // 41. HP 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\HP\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                }

                // 42. Lenovo 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Lenovo\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("GestureEnable", 0, RegistryValueKind.DWord);
                }

                // 43. ASUS 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\ASUS\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("GestureMode", 0, RegistryValueKind.DWord);
                }

                // 44. Acer 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Acer\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                }

                // 45. MSI 터치패드 설정 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\MSI\TouchPad", true))
                {
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("GestureEnable", 0, RegistryValueKind.DWord);
                }

                // 46. 추가 Windows 제스처 정책 설정
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows\TouchInput", true))
                {
                    key.SetValue("DisableTouchInput", 0, RegistryValueKind.DWord); // 터치 입력은 유지하되 제스처만 비활성화
                    key.SetValue("DisableGestures", 1, RegistryValueKind.DWord);
                }

                // 47. Windows 멀티터치 제스처 전역 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Gestures", true))
                {
                    key.SetValue("Enabled", 0, RegistryValueKind.DWord);
                    key.SetValue("ThreeFingerGestures", 0, RegistryValueKind.DWord);
                    key.SetValue("FourFingerGestures", 0, RegistryValueKind.DWord);
                }

                // 48. Windows 터치 제스처 인식 서비스 비활성화
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\TouchHID", true))
                {
                    key.SetValue("Start", 4, RegistryValueKind.DWord); // 4 = 비활성화
                }

                // 49. HID 터치 디바이스 제스처 비활성화
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Enum\HID", true))
                {
                    // HID 디바이스의 제스처 기능 비활성화를 위한 전역 설정
                    key.SetValue("DisableGestures", 1, RegistryValueKind.DWord);
                }

                // 50. 터치 및 펜 서비스 제스처 비활성화
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\PolicyManager\current\device\Touch", true))
                {
                    key.SetValue("DisableGestures", 1, RegistryValueKind.DWord);
                }

                // ------ 기존 알림 비활성화 설정 ------
                // Notification Settings
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows\Explorer", true))
                {
                    key.SetValue("DisableNotificationCenter", 1, RegistryValueKind.DWord);
                }

                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications", true))
                {
                    key.SetValue("ToastEnabled", 0, RegistryValueKind.DWord);
                }

                // ------ 추가 알림 비활성화 설정 ------
                // 1. 시스템 알림 비활성화 (Focus Assist 설정 포함)
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings", true))
                {
                    key.SetValue("NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND", 0, RegistryValueKind.DWord);
                    key.SetValue("NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK", 0, RegistryValueKind.DWord);
                    key.SetValue("NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK", 0, RegistryValueKind.DWord);
                }

                // 2. 포커스 어시스트 (방해 금지 모드) 설정
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Focus Assist", true))
                {
                    // 0: 꺼짐, 1: 우선 순위만, 2: 알람만
                    key.SetValue("FocusLevelAll", 2, RegistryValueKind.DWord);
                    key.SetValue("FocusLevelPriority", 1, RegistryValueKind.DWord);
                    key.SetValue("Settings", 1, RegistryValueKind.DWord);
                }

                // 3. 시작 메뉴 알림 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced", true))
                {
                    key.SetValue("ShowSyncProviderNotifications", 0, RegistryValueKind.DWord);
                    key.SetValue("TaskbarBadges", 0, RegistryValueKind.DWord);
                    key.SetValue("EnableBalloonTips", 0, RegistryValueKind.DWord);
                }

                // 4. Action Center 비활성화 (Windows 10/11)
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell", true))
                {
                    key.SetValue("UseActionCenterExperience", 0, RegistryValueKind.DWord);
                }

                // 5. 시스템 정책 레벨에서 알림 비활성화
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows\Explorer", true))
                {
                    key.SetValue("DisableNotificationCenter", 1, RegistryValueKind.DWord);
                    key.SetValue("DisableToastNotification", 1, RegistryValueKind.DWord);
                }

                // 6. Windows 10/11 Quiet Hours (집중 시간) 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\QuietHours", true))
                {
                    key.SetValue("Enabled", 0, RegistryValueKind.DWord);
                }

                // 7. Windows 작업 표시줄의 배지 알림 비활성화
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced", true))
                {
                    key.SetValue("TaskbarBadges", 0, RegistryValueKind.DWord);
                }

                // 8. 앱별 알림 설정 - 모든 앱의 알림 비활성화
                // 주요 Windows 앱의 알림 비활성화
                string[] coreApps = new[] {
                    "Windows.SystemToast.AutoPlay",
                    "Windows.SystemToast.BackgroundAccess",
                    "Windows.SystemToast.Bluetooth",
                    "Windows.SystemToast.DeviceConsolidation",
                    "Windows.SystemToast.Display",
                    "Windows.SystemToast.Print.Notification",
                    "Windows.SystemToast.SecurityAndMaintenance",
                    "Windows.SystemToast.WindowsTip",
                    "Microsoft.Windows.Cortana",
                    "Microsoft.Windows.SecHealthUI",
                    "Microsoft.Windows.WindowsUpdate"
                };

                foreach (string app in coreApps)
                {
                    using (RegistryKey key = Registry.CurrentUser.CreateSubKey($@"SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\{app}", true))
                    {
                        key.SetValue("Enabled", 0, RegistryValueKind.DWord);
                        key.SetValue("ShowInActionCenter", 0, RegistryValueKind.DWord);
                    }
                }

                // Tablet Mode Settings
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell", true))
                {
                    key.SetValue("TabletMode", 0, RegistryValueKind.DWord);
                    key.SetValue("SignInMode", 1, RegistryValueKind.DWord);
                }

                // Edge UI Settings
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows\EdgeUI", true))
                {
                    key.SetValue("AllowEdgeSwipe", 0, RegistryValueKind.DWord);
                }

                // Cortana Settings
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows\Windows Search", true))
                {
                    key.SetValue("AllowCortana", 0, RegistryValueKind.DWord);
                }

                ExecuteCommand("powercfg", "-duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61");
                ExecuteCommand("powercfg", "-setactive e9a42b02-d5df-448d-aa00-03f14749eb61");
                
                // 작업표시줄 설정이 적용되도록 탐색기 재시작
                RestartExplorer();
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to apply signage settings", ex);
            }
        }
        
        /// <summary>
        /// 사이니지 100% 배율 설정이 현재 적용되어 있는지 확인합니다.
        /// </summary>
        public static bool IsSignageScalingApplied()
        {
            try
            {
                using (RegistryKey desktopKey = Registry.CurrentUser.OpenSubKey(@"Control Panel\Desktop"))
                {
                    if (desktopKey == null ||
                        !TryGetDwordValue(desktopKey, "DelayLockInterval", out int delayLockInterval) || delayLockInterval != 0 ||
                        !TryGetDwordValue(desktopKey, "LogPixels", out int logPixels) || logPixels != SignageLogPixels ||
                        !TryGetDwordValue(desktopKey, "Win8DpiScaling", out int win8DpiScaling) || win8DpiScaling != 1)
                    {
                        return false;
                    }
                }

                using (RegistryKey windowMetricsKey = Registry.CurrentUser.OpenSubKey(@"Control Panel\Desktop\WindowMetrics"))
                {
                    if (windowMetricsKey == null ||
                        !TryGetDwordValue(windowMetricsKey, "AppliedDPI", out int appliedDpi) || appliedDpi != SignageLogPixels)
                    {
                        return false;
                    }
                }

                using (RegistryKey perMonitorSettingsKey = Registry.CurrentUser.OpenSubKey(@"Control Panel\Desktop\PerMonitorSettings"))
                {
                    if (perMonitorSettingsKey != null && perMonitorSettingsKey.SubKeyCount > 0)
                    {
                        return false;
                    }
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 탐색기 프로세스를 재시작합니다.
        /// </summary>
        private static void RestartExplorer()
        {
            try
            {
                // 현재 실행 중인 explorer.exe 프로세스 종료
                Process[] explorerProcesses = Process.GetProcessesByName("explorer");
                foreach (Process explorerProcess in explorerProcesses)
                {
                    explorerProcess.Kill();
                    explorerProcess.WaitForExit();
                }

                // 잠시 대기
                Thread.Sleep(1000);

                // explorer.exe 다시 시작
                Process.Start("explorer.exe");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"탐색기 재시작 중 오류 발생: {ex.Message}");
            }
        }

        private static void ApplySignageDesktopScaling()
        {
            using (RegistryKey desktopKey = Registry.CurrentUser.CreateSubKey(@"Control Panel\Desktop", true))
            {
                desktopKey.SetValue("DelayLockInterval", 0, RegistryValueKind.DWord);
                desktopKey.SetValue("LogPixels", SignageLogPixels, RegistryValueKind.DWord);
                desktopKey.SetValue("Win8DpiScaling", 1, RegistryValueKind.DWord);
            }

            using (RegistryKey windowMetricsKey = Registry.CurrentUser.CreateSubKey(@"Control Panel\Desktop\WindowMetrics", true))
            {
                windowMetricsKey.SetValue("AppliedDPI", SignageLogPixels, RegistryValueKind.DWord);
            }

            Registry.CurrentUser.DeleteSubKeyTree(@"Control Panel\Desktop\PerMonitorSettings", false);
        }

        private static bool TryGetDwordValue(RegistryKey key, string valueName, out int value)
        {
            value = 0;

            object rawValue = key.GetValue(valueName);
            if (rawValue == null)
            {
                return false;
            }

            if (rawValue is int intValue)
            {
                value = intValue;
                return true;
            }

            try
            {
                value = Convert.ToInt32(rawValue);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static void SetWindowsUpdateEnabled(bool enabled)
        {
            try
            {
                ServiceController sc = new ServiceController("wuauserv");

                if (enabled)
                {
                    Debug.WriteLine("Windows Update 서비스를 활성화합니다...\n");

                    EnableService("wuauserv");
                    EnableService("WaaSMedicSvc");
                    EnableService("UsoSvc");

                    EnableScheduledTasks();
                    RestoreRegistry();
                    RestoreHostsFile();

                    Debug.WriteLine("Windows Update 서비스가 활성화되었습니다.\n");
                }
                else
                {
                    Debug.WriteLine("Windows Update 서비스를 비활성화 및 중지합니다...\n");

                    DisableService("wuauserv");
                    DisableService("WaaSMedicSvc");
                    DisableService("UsoSvc");

                    DisableScheduledTasks();
                    SetRegistry();
                    BlockHostsFile();

                    Debug.WriteLine("Windows Update 서비스가 비활성화되었습니다.\n");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Failed to set Windows Update status: {ex.Message}", ex);
            }
        }

        #region Windows Update Helper Methods
        static void DisableService(string serviceName)
        {
            ExecuteCommand("sc", $"stop {serviceName}");
            ExecuteCommand("sc", $"config {serviceName} start= disabled");
        }

        static void DisableScheduledTasks()
        {
            string[] tasks = new[]
            {
            @"\Microsoft\Windows\UpdateOrchestrator\ScheduleScan",
            @"\Microsoft\Windows\WindowsUpdate\Scheduled Start"
        };

            foreach (var task in tasks)
            {
                ExecuteCommand("schtasks", $"/Change /TN \"{task}\" /Disable");
            }
        }

        static void BlockHostsFile()
        {
            string hostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
            string[] blockEntries = new[]
            {
            "0.0.0.0 update.microsoft.com",
            "0.0.0.0 windowsupdate.microsoft.com",
            "0.0.0.0 download.windowsupdate.com"
        };

            var lines = File.ReadAllLines(hostsPath).ToList();
            foreach (var entry in blockEntries)
            {
                if (!lines.Contains(entry))
                    lines.Add(entry);
            }

            File.WriteAllLines(hostsPath, lines);
        }

        static void EnableService(string serviceName)
        {
            ExecuteCommand("sc", $"config {serviceName} start= auto");
            ExecuteCommand("sc", $"start {serviceName}");
        }

        static void EnableScheduledTasks()
        {
            string[] tasks = new[]
            {
            @"\Microsoft\Windows\UpdateOrchestrator\ScheduleScan",
            @"\Microsoft\Windows\WindowsUpdate\Scheduled Start"
        };

            foreach (var task in tasks)
            {
                ExecuteCommand("schtasks", $"/Change /TN \"{task}\" /Enable");
            }
        }

        static void RestoreRegistry()
        {
            const string baseKey = @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";
            const string auKey = baseKey + @"\AU";

            try
            {
                RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", writable: true);
                key?.DeleteValue("DoNotConnectToWindowsUpdateInternetLocations", false);

                RegistryKey au = key?.OpenSubKey("AU", writable: true);
                au?.DeleteValue("NoAutoUpdate", false);
                au?.DeleteValue("AUOptions", false);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"레지스트리 복원 중 오류: {ex.Message}");
            }
        }

        static void RestoreHostsFile()
        {
            string hostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
            string[] blockEntries = new[]
            {
            "0.0.0.0 update.microsoft.com",
            "0.0.0.0 windowsupdate.microsoft.com",
            "0.0.0.0 download.windowsupdate.com"
        };

            var lines = File.ReadAllLines(hostsPath).ToList();
            lines = lines.Where(line => !blockEntries.Contains(line.Trim())).ToList();
            File.WriteAllLines(hostsPath, lines);
        }

        static void SetRegistry()
        {
            const string keyPath = @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
            Registry.SetValue(keyPath, "NoAutoUpdate", 1, RegistryValueKind.DWord);
            Registry.SetValue(keyPath, "AUOptions", 1, RegistryValueKind.DWord); // 1: 알림만

            const string wuKey = @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";
            Registry.SetValue(wuKey, "DoNotConnectToWindowsUpdateInternetLocations", 1, RegistryValueKind.DWord);
        }

        #endregion

        static void ExecuteCommand(string fileName, string arguments)
        {
            using (Process process = new Process())
            {
                process.StartInfo.FileName = fileName;
                process.StartInfo.Arguments = arguments;
                process.StartInfo.UseShellExecute = true;
                process.StartInfo.Verb = "runas";
                process.StartInfo.CreateNoWindow = true;

                process.Start();
                process.WaitForExit();
            }
        }

        /// <summary>
        /// 가상 데스크톱과 태스크 뷰 기능을 활성화 또는 비활성화합니다.
        /// </summary>
        /// <param name="enabled">true면 활성화, false면 비활성화</param>
        public static void SetVirtualDesktopAndTaskViewEnabled(bool enabled)
        {
            try
            {
                // 가상 데스크톱 관련 레지스트리 설정
                using (RegistryKey explorerKey = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", true))
                {
                    if (!enabled)
                    {
                        // 가상 데스크톱 기능 비활성화
                        explorerKey.SetValue("VirtualDesktopTaskViewEnabled", 0, RegistryValueKind.DWord);
                        // 가상 데스크톱 간 애니메이션 비활성화
                        explorerKey.SetValue("EnableSwitchVirtualDesktopAnimation", 0, RegistryValueKind.DWord);
                    }
                    else
                    {
                        // 기본값으로 복원 (기본적으로 활성화됨)
                        explorerKey.DeleteValue("VirtualDesktopTaskViewEnabled", false);
                        explorerKey.DeleteValue("EnableSwitchVirtualDesktopAnimation", false);
                    }
                }

                // 엣지 스와이프 제스처 설정 (가상 데스크톱 관련)
                using (RegistryKey edgeUIKey = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows\EdgeUI", true))
                {
                    if (!enabled)
                    {
                        // 엣지 스와이프 제스처 비활성화
                        edgeUIKey.SetValue("AllowEdgeSwipe", 0, RegistryValueKind.DWord);
                    }
                    else
                    {
                        // 엣지 스와이프 제스처 활성화 또는 기본값 복원
                        edgeUIKey.DeleteValue("AllowEdgeSwipe", false);
                    }
                }

                // 작업 뷰 단축키 비활성화 (Win + Tab)
                using (RegistryKey explorerKey = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", true))
                {
                    if (!enabled)
                    {
                        // 작업 뷰 단축키 비활성화
                        explorerKey.SetValue("DisableTaskViewShortcut", 1, RegistryValueKind.DWord);
                    }
                    else
                    {
                        // 작업 뷰 단축키 활성화
                        explorerKey.DeleteValue("DisableTaskViewShortcut", false);
                    }
                }

                // 익스플로러 프로세스 재시작을 통해 변경사항 적용
                RestartExplorer();
            }
            catch (Exception ex)
            {
                throw new Exception($"가상 데스크톱 및 태스크 뷰 설정 변경 실패: {ex.Message}", ex);
            }
        }
    }
}
