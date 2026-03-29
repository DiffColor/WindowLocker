using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Microsoft.Win32;
using WindowLocker.Managers;
using WindowLocker.ViewModels;

namespace WindowLocker.Views
{
    public partial class ControlDialog : Window
    {
        public event Action ShowMainWindow;
        private bool _isInitializing;

        private void UpdateSignageButtonState()
        {
            bool isAnySettingNotApplied = false;

            try
            {
                // 1. 화면 설정 확인
                // Lock Screen Settings
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\Personalization"))
                {
                    if (key == null || key.GetValue("NoLockScreen") == null || (int)key.GetValue("NoLockScreen") != 1)
                        isAnySettingNotApplied = true;
                }

                // Screen Saver Settings
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"))
                {
                    if (key == null || 
                        key.GetValue("ScreenSaveActive") == null || key.GetValue("ScreenSaveActive").ToString() != "0" ||
                        key.GetValue("SCRNSAVE.EXE") == null || key.GetValue("SCRNSAVE.EXE").ToString() != "" ||
                        key.GetValue("ScreenSaverIsSecure") == null || key.GetValue("ScreenSaverIsSecure").ToString() != "0")
                        isAnySettingNotApplied = true;
                }

                // 2. 전원 설정 확인
                // Power Settings
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Power"))
                {
                    if (key == null || key.GetValue("CsEnabled") == null || (int)key.GetValue("CsEnabled") != 0)
                        isAnySettingNotApplied = true;
                }

                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Power"))
                {
                    if (key == null || 
                        key.GetValue("HiberbootEnabled") == null || (int)key.GetValue("HiberbootEnabled") != 0 ||
                        key.GetValue("AwayModeEnabled") == null || (int)key.GetValue("AwayModeEnabled") != 1)
                        isAnySettingNotApplied = true;
                }

                // 3. 데스크톱 설정 확인
                if (!SystemManager.IsSignageScalingApplied())
                    isAnySettingNotApplied = true;

                // 4. 작업표시줄 설정 확인
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"))
                {
                    if (key == null || key.GetValue("MMTaskbarEnabled") == null || (int)key.GetValue("MMTaskbarEnabled") != 0)
                        isAnySettingNotApplied = true;
                }

                // 5. 멀티 터치 제스처 비활성화 확인
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\PrecisionTouchPad"))
                {
                    if (key != null) // 이 설정은 모든 PC에 있지 않을 수 있음
                    {
                        if (key.GetValue("ThreeFingerGestures") != null && (int)key.GetValue("ThreeFingerGestures") != 0)
                            isAnySettingNotApplied = true;
                        
                        if (key.GetValue("FourFingerGestures") != null && (int)key.GetValue("FourFingerGestures") != 0)
                            isAnySettingNotApplied = true;

                        if (key.GetValue("ThreeFingerSlideEnabled") != null && (int)key.GetValue("ThreeFingerSlideEnabled") != 0)
                            isAnySettingNotApplied = true;

                        if (key.GetValue("FourFingerSlideEnabled") != null && (int)key.GetValue("FourFingerSlideEnabled") != 0)
                            isAnySettingNotApplied = true;
                    }
                }

                // 5-1. Synaptics 터치패드 설정 확인
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Synaptics\SynTP\TouchPadPS2"))
                {
                    if (key != null)
                    {
                        if (key.GetValue("3FingerGestures") != null && (int)key.GetValue("3FingerGestures") != 0)
                            isAnySettingNotApplied = true;
                        if (key.GetValue("4FingerGestures") != null && (int)key.GetValue("4FingerGestures") != 0)
                            isAnySettingNotApplied = true;
                        if (key.GetValue("ThreeFingerGestures") != null && (int)key.GetValue("ThreeFingerGestures") != 0)
                            isAnySettingNotApplied = true;
                        if (key.GetValue("FourFingerGestures") != null && (int)key.GetValue("FourFingerGestures") != 0)
                            isAnySettingNotApplied = true;
                    }
                }

                // 5-2. ELAN 터치패드 설정 확인
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Elantech\SmartPad"))
                {
                    if (key != null)
                    {
                        if (key.GetValue("Gesture_3F_Enable") != null && (int)key.GetValue("Gesture_3F_Enable") != 0)
                            isAnySettingNotApplied = true;
                        if (key.GetValue("Gesture_4F_Enable") != null && (int)key.GetValue("Gesture_4F_Enable") != 0)
                            isAnySettingNotApplied = true;
                        if (key.GetValue("ThreeFingerGestures") != null && (int)key.GetValue("ThreeFingerGestures") != 0)
                            isAnySettingNotApplied = true;
                        if (key.GetValue("FourFingerGestures") != null && (int)key.GetValue("FourFingerGestures") != 0)
                            isAnySettingNotApplied = true;
                    }
                }

                // 5-3. ALPS 터치패드 설정 확인
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Alps\Apoint"))
                {
                    if (key != null)
                    {
                        if (key.GetValue("ThreeFingerGestures") != null && (int)key.GetValue("ThreeFingerGestures") != 0)
                            isAnySettingNotApplied = true;
                        if (key.GetValue("FourFingerGestures") != null && (int)key.GetValue("FourFingerGestures") != 0)
                            isAnySettingNotApplied = true;
                    }
                }

                // 5-4. Cirque 터치패드 설정 확인
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Cirque\GlidePoint"))
                {
                    if (key != null)
                    {
                        if (key.GetValue("ThreeFingerGestures") != null && (int)key.GetValue("ThreeFingerGestures") != 0)
                            isAnySettingNotApplied = true;
                        if (key.GetValue("FourFingerGestures") != null && (int)key.GetValue("FourFingerGestures") != 0)
                            isAnySettingNotApplied = true;
                        if (key.GetValue("AdvancedGestures") != null && (int)key.GetValue("AdvancedGestures") != 0)
                            isAnySettingNotApplied = true;
                    }
                }

                // 5-5. FocalTech 터치패드 설정 확인
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\FocalTech\TouchPad"))
                {
                    if (key != null)
                    {
                        if (key.GetValue("ThreeFingerGestures") != null && (int)key.GetValue("ThreeFingerGestures") != 0)
                            isAnySettingNotApplied = true;
                        if (key.GetValue("FourFingerGestures") != null && (int)key.GetValue("FourFingerGestures") != 0)
                            isAnySettingNotApplied = true;
                        if (key.GetValue("GestureEnable") != null && (int)key.GetValue("GestureEnable") != 0)
                            isAnySettingNotApplied = true;
                    }
                }

                // 5-6. Goodix 터치패드 설정 확인
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Goodix\TouchPad"))
                {
                    if (key != null)
                    {
                        if (key.GetValue("ThreeFingerGestures") != null && (int)key.GetValue("ThreeFingerGestures") != 0)
                            isAnySettingNotApplied = true;
                        if (key.GetValue("FourFingerGestures") != null && (int)key.GetValue("FourFingerGestures") != 0)
                            isAnySettingNotApplied = true;
                    }
                }

                // 5-7. 기타 주요 터치패드 제조사들 설정 확인 (간소화된 체크)
                string[] touchpadManufacturers = new[] {
                    @"Software\Weida\TouchPad",
                    @"Software\Sentelic\TouchPad", 
                    @"Software\Atmel\TouchPad",
                    @"Software\Validity\TouchPad",
                    @"Software\Wacom\TouchPad",
                    @"Software\Realtek\TouchPad",
                    @"Software\Broadcom\TouchPad",
                    @"Software\Cypress\TouchPad",
                    @"Software\Ilitek\TouchPad",
                    @"Software\Pixart\TouchPad",
                    @"Software\Novatek\TouchPad",
                    @"Software\Himax\TouchPad",
                    @"Software\Raydium\TouchPad",
                    @"Software\Melfas\TouchPad",
                    @"Software\Silead\TouchPad",
                    @"Software\Chipone\TouchPad"
                };

                foreach (string manufacturer in touchpadManufacturers)
                {
                    using (RegistryKey key = Registry.CurrentUser.OpenSubKey(manufacturer))
                    {
                        if (key != null)
                        {
                            if (key.GetValue("ThreeFingerGestures") != null && (int)key.GetValue("ThreeFingerGestures") != 0)
                                isAnySettingNotApplied = true;
                            if (key.GetValue("FourFingerGestures") != null && (int)key.GetValue("FourFingerGestures") != 0)
                                isAnySettingNotApplied = true;
                            if (key.GetValue("GestureEnable") != null && (int)key.GetValue("GestureEnable") != 0)
                                isAnySettingNotApplied = true;
                        }
                    }
                }

                // 5-8. 추가 터치 제스처 설정 확인
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Control Panel\Desktop"))
                {
                    if (key != null)
                    {
                        if (key.GetValue("TouchGestureSetting") != null && (int)key.GetValue("TouchGestureSetting") != 0)
                            isAnySettingNotApplied = true;
                    }
                }

                // 6. 알림 설정 확인
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\Explorer"))
                {
                    if (key == null || key.GetValue("DisableNotificationCenter") == null || (int)key.GetValue("DisableNotificationCenter") != 1)
                        isAnySettingNotApplied = true;
                }

                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications"))
                {
                    if (key == null || key.GetValue("ToastEnabled") == null || (int)key.GetValue("ToastEnabled") != 0)
                        isAnySettingNotApplied = true;
                }

                // 7. 태블릿 모드 설정 확인
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell"))
                {
                    if (key == null || 
                        key.GetValue("TabletMode") == null || (int)key.GetValue("TabletMode") != 0 ||
                        key.GetValue("SignInMode") == null || (int)key.GetValue("SignInMode") != 1 ||
                        key.GetValue("UseActionCenterExperience") == null || (int)key.GetValue("UseActionCenterExperience") != 0)
                        isAnySettingNotApplied = true;
                }

                // 8. Edge UI 설정 확인
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\EdgeUI"))
                {
                    if (key == null || key.GetValue("AllowEdgeSwipe") == null || (int)key.GetValue("AllowEdgeSwipe") != 0)
                        isAnySettingNotApplied = true;
                }

                // 9. 코타나 설정 확인
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\Windows Search"))
                {
                    if (key == null || key.GetValue("AllowCortana") == null || (int)key.GetValue("AllowCortana") != 0)
                        isAnySettingNotApplied = true;
                }

                // 10. 포커스 어시스트 설정 확인
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Focus Assist"))
                {
                    if (key != null) // 이 설정은 모든 PC에 있지 않을 수 있음
                    {
                        if (key.GetValue("FocusLevelAll") != null && (int)key.GetValue("FocusLevelAll") != 2)
                            isAnySettingNotApplied = true;
                        
                        if (key.GetValue("FocusLevelPriority") != null && (int)key.GetValue("FocusLevelPriority") != 1)
                            isAnySettingNotApplied = true;
                    }
                }

                signageSettingsButton.IsEnabled = isAnySettingNotApplied;
            }
            catch (Exception)
            {
                // 예외 발생 시 버튼 활성화
                signageSettingsButton.IsEnabled = true;
            }
        }

        private async void HackingPreventionToggle_Click(object sender, RoutedEventArgs e)
        {
            if (_isInitializing) return;

            try
            {
                Mouse.OverrideCursor = Cursors.Wait;

                if ((bool)HackingPreventionToggle.IsChecked)               {
                    await Task.Run(() =>
                    {
                        MainWindow.Instance.sViewModel.EnablePreventHack();
                    });

                    MessageBox.Show(MainWindow.Instance,
						(string)Application.Current.FindResource("MsgHackingPreventionSuccess"),
                        (string)Application.Current.FindResource("MsgSuccess"),
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }
                else
                {
                    await Task.Run(() =>
                    {
                        MainWindow.Instance.sViewModel.DisablePreventHack();
                    });

                    MessageBox.Show(MainWindow.Instance,
						(string)Application.Current.FindResource("MsgHackingPreventionDisabled"),
                        (string)Application.Current.FindResource("MsgSuccess"),
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(MainWindow.Instance,
					string.Format((string)Application.Current.FindResource("MsgHackingPreventionError"), ex.Message),
                    (string)Application.Current.FindResource("MsgError"),
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
            finally
            {
                Mouse.OverrideCursor = null;
            }
        }

        private async void ApplySignageSettings_Click(object sender, RoutedEventArgs e)
        {
            await MainWindow.Instance.sViewModel.ApplySignageSettingsAsync();
            UpdateSignageButtonState();
        }

        private void DetailedSettings_Click(object sender, RoutedEventArgs e)
        {

            ShowMainWindow?.Invoke();
            this.Hide();
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            this.Hide();
        }

        protected override void OnKeyDown(System.Windows.Input.KeyEventArgs e)
        {
            if (e.Key == System.Windows.Input.Key.Escape)
            {
                this.Hide();
            }
            base.OnKeyDown(e);
        }

        public ControlDialog()
        {
            InitializeComponent();
            _isInitializing = true;
            
            HackingPreventionToggle.IsChecked = MainWindow.Instance.sViewModel.IsSystemLocked;
            UpdateSignageButtonState();  // Initial button state check
            _isInitializing = false;
        }

        private void Window_IsVisibleChanged(object sender, DependencyPropertyChangedEventArgs e)
        {
            if (IsVisible)
            {
                //Dispatcher.Invoke(new Action(() =>
                //{
                //    this.Topmost = true;
                //}));

                //Thread.Sleep(200);

                //Dispatcher.Invoke(new Action(() =>
                //{
                //    this.Topmost = false;
                //}));
            }
        }
    }
}
