using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;
using WindowLocker.Commands;
using WindowLocker.Managers;
using WindowLocker.Utilities;

namespace WindowLocker.ViewModels
{
    public class MainViewModel : INotifyPropertyChanged
    {       
        private bool _isSysytemLocked;
        public bool IsSystemLocked
        {
            get => _isSysytemLocked;
            set
            {
                if (_isSysytemLocked != value)
                {
                    _isSysytemLocked = value;
                    Properties.Settings.Default.IsSystemLocked = value;
                    Properties.Settings.Default.Save();
                    OnPropertyChanged(nameof(IsSystemLocked));
                }
            }
        }

        public PasswordBox AutoLoginPasswordBox { get; set; }
        public bool ShowRestartAsAdmin { get; set; } = false;
        private bool _isApplyingProtectedSettings;

        public bool IsApplyingProtectedSettings
        {
            get => _isApplyingProtectedSettings;
            private set
            {
                if (_isApplyingProtectedSettings != value)
                {
                    _isApplyingProtectedSettings = value;
                    OnPropertyChanged(nameof(IsApplyingProtectedSettings));
                    CommandManager.InvalidateRequerySuggested();
                }
            }
        }

        // Settings properties
        private bool _blackBackground;
        public bool BlackBackground
        {
            get => _blackBackground;
            set
            {
                if (_blackBackground != value)
                {
                    _blackBackground = value;
                    Properties.Settings.Default.BlackBackground = value;
                    Properties.Settings.Default.Save();
                    OnPropertyChanged(nameof(BlackBackground));
                }
            }
        }

        private bool _hideDesktopIcons;
        public bool HideDesktopIcons
        {
            get => _hideDesktopIcons;
            set
            {
                if (_hideDesktopIcons != value)
                {
                    _hideDesktopIcons = value;
                    Properties.Settings.Default.HideDesktopIcons = value;
                    Properties.Settings.Default.Save();
                    OnPropertyChanged(nameof(HideDesktopIcons));
                }
            }
        }

        private bool _hideTaskbar;
        public bool HideTaskbar
        {
            get => _hideTaskbar;
            set
            {
                if (_hideTaskbar != value)
                {
                    _hideTaskbar = value;
                    Properties.Settings.Default.HideTaskbar = value;
                    Properties.Settings.Default.Save();
                    OnPropertyChanged(nameof(HideTaskbar));
                }
            }
        }

        private bool _disableSettingsApp;
        public bool DisableSettingsApp
        {
            get => _disableSettingsApp;
            set
            {
                if (_disableSettingsApp != value)
                {
                    _disableSettingsApp = value;
                    Properties.Settings.Default.DisableSettingsApp = value;
                    Properties.Settings.Default.Save();
                    OnPropertyChanged(nameof(DisableSettingsApp));
                }
            }
        }

        private bool _disableTaskManager;
        public bool DisableTaskManager
        {
            get => _disableTaskManager;
            set
            {
                if (_disableTaskManager != value)
                {
                    _disableTaskManager = value;
                    Properties.Settings.Default.DisableTaskManager = value;
                    Properties.Settings.Default.Save();
                    OnPropertyChanged(nameof(DisableTaskManager));
                }
            }
        }

        private bool _disableHardwareAcceleration;
        public bool DisableHardwareAcceleration
        {
            get => _disableHardwareAcceleration;
            set
            {
                if (_disableHardwareAcceleration != value)
                {
                    _disableHardwareAcceleration = value;
                    Properties.Settings.Default.DisableHardwareAcceleration = value;
                    Properties.Settings.Default.Save();
                    OnPropertyChanged(nameof(DisableHardwareAcceleration));
                }
            }
        }

        private bool _disableRemoteDesktop;
        public bool DisableRemoteDesktop
        {
            get => _disableRemoteDesktop;
            set
            {
                if (_disableRemoteDesktop != value)
                {
                    _disableRemoteDesktop = value;
                    Properties.Settings.Default.DisableRemoteDesktop = value;
                    Properties.Settings.Default.Save();
                    OnPropertyChanged(nameof(DisableRemoteDesktop));
                }
            }
        }

        private bool _disableCommandPrompt;
        public bool DisableCommandPrompt
        {
            get => _disableCommandPrompt;
            set
            {
                if (_disableCommandPrompt != value)
                {
                    _disableCommandPrompt = value;
                    Properties.Settings.Default.DisableCommandPrompt = value;
                    Properties.Settings.Default.Save();
                    OnPropertyChanged(nameof(DisableCommandPrompt));
                }
            }
        }

        private bool _disablePowerShell;
        public bool DisablePowerShell
        {
            get => _disablePowerShell;
            set
            {
                if (_disablePowerShell != value)
                {
                    _disablePowerShell = value;
                    Properties.Settings.Default.DisablePowerShell = value;
                    Properties.Settings.Default.Save();
                    OnPropertyChanged(nameof(DisablePowerShell));
                }
            }
        }

        private bool _disableRegistryEditor;
        public bool DisableRegistryEditor
        {
            get => _disableRegistryEditor;
            set
            {
                if (_disableRegistryEditor != value)
                {
                    _disableRegistryEditor = value;
                    Properties.Settings.Default.DisableRegistryEditor = value;
                    Properties.Settings.Default.Save();
                    OnPropertyChanged(nameof(DisableRegistryEditor));
                }
            }
        }

        private bool _disableAdministrator;
        public bool DisableAdministrator
        {
            get => _disableAdministrator;
            set
            {
                if (_disableAdministrator != value)
                {
                    _disableAdministrator = value;
                    Properties.Settings.Default.DisableAdministrator = value;
                    Properties.Settings.Default.Save();
                    OnPropertyChanged(nameof(DisableAdministrator));
                }
            }
        }

        private bool _enableAutoLogin;
        public bool EnableAutoLogin
        {
            get => _enableAutoLogin;
            set
            {
                if (_enableAutoLogin != value)
                {
                    _enableAutoLogin = value;
                    Properties.Settings.Default.EnableAutoLogin = value;
                    Properties.Settings.Default.Save();
                    OnPropertyChanged(nameof(EnableAutoLogin));
                }
            }
        }

        private string _autoLoginUsername;
        public string AutoLoginUsername
        {
            get => _autoLoginUsername;
            set
            {
                if (_autoLoginUsername != value)
                {
                    _autoLoginUsername = value;
                    Properties.Settings.Default.AutoLoginUsername = value;
                    Properties.Settings.Default.Save();
                    OnPropertyChanged(nameof(AutoLoginUsername));
                }
            }
        }

        private string _autoLoginPassword;
        public string AutoLoginPassword
        {
            get => _autoLoginPassword;
            set
            {
                if (_autoLoginPassword != value)
                {
                    _autoLoginPassword = value;
                    Properties.Settings.Default.AutoLoginPassword = value;
                    Properties.Settings.Default.Save();
                    OnPropertyChanged(nameof(AutoLoginPassword));
                }
            }
        }

        private bool _disableSmartAppControl;
        public bool DisableSmartAppControl
        {
            get => _disableSmartAppControl;
            set
            {
                if (_disableSmartAppControl != value)
                {
                    _disableSmartAppControl = value;
                    Properties.Settings.Default.DisableSmartAppControl = value;
                    Properties.Settings.Default.Save();
                    OnPropertyChanged(nameof(DisableSmartAppControl));
                }
            }
        }
        
        private bool _disableUAC;
        public bool DisableUAC
        {
            get => _disableUAC;
            set
            {
                if (_disableUAC != value)
                {
                    _disableUAC = value;
                    Properties.Settings.Default.DisableUAC = value;
                    Properties.Settings.Default.Save();
                    OnPropertyChanged(nameof(DisableUAC));
                }
            }
        }

        private bool _disableWindowsUpdate;
        public bool DisableWindowsUpdate
        {
            get => _disableWindowsUpdate;
            set
            {
                if (_disableWindowsUpdate != value)
                {
                    _disableWindowsUpdate = value;
                    Properties.Settings.Default.DisableWindowsUpdate = value;
                    Properties.Settings.Default.Save();
                    OnPropertyChanged(nameof(DisableWindowsUpdate));
                }
            }
        }

        public ICommand ApplyDesktopSettingsCommand { get; }
        public ICommand ApplySystemControlsCommand { get; }
        public ICommand ApplySecuritySettingsCommand { get; }
        public ICommand ApplySignageSettingsCommand { get; }
        public ICommand RestartAsAdminCommand { get; }
        public ICommand ApplyAutoLoginSettingsCommand { get; }

        public MainViewModel()
        {
            ApplyDesktopSettingsCommand = new RelayCommand(ApplyDesktopSettings);
            ApplySystemControlsCommand = new RelayCommand(ApplySystemControls);
            ApplySecuritySettingsCommand = new RelayCommand(async () => await ApplySecuritySettingsAsync(), CanApplyProtectedSettings);
            ApplySignageSettingsCommand = new RelayCommand(async () => await ApplySignageSettingsAsync(), CanApplyProtectedSettings);
            RestartAsAdminCommand = new RelayCommand(RestartAsAdmin);
            ApplyAutoLoginSettingsCommand = new RelayCommand(ApplyAutoLoginSettings);

            // 저장된 자동 로그인 설정 불러오기
            if (string.IsNullOrEmpty(Properties.Settings.Default.AutoLoginUsername))
            {
                AutoLoginUsername = Environment.UserName;
            }
            else
            {
                AutoLoginUsername = Properties.Settings.Default.AutoLoginUsername;
            }

            InitializeProperties();
        }

        private void ApplyAutoLoginSettings()
        {
            try
            {
                if (!SystemUtilities.IsRunningAsAdmin())
                {
                    if (MainWindow.Instance.IsVisible)
                        MessageBox.Show(MainWindow.Instance,
							(string)Application.Current.FindResource("MsgAdminRequired"),
                            (string)Application.Current.FindResource("MsgWarning"),
                            MessageBoxButton.OK,
                            MessageBoxImage.Warning);
                    return;
                }

                // Update password before applying settings
                UpdateAutoLoginPassword();

                Properties.Settings.Default.AutoLoginUsername = AutoLoginUsername;
                Properties.Settings.Default.AutoLoginPassword = AutoLoginPassword;
                Properties.Settings.Default.EnableAutoLogin = EnableAutoLogin;
                Properties.Settings.Default.Save();

				SecurityManager.SetAutoLogin(EnableAutoLogin, AutoLoginUsername, AutoLoginPassword);

                Debug.WriteLine($"Auto login settings applied: Enabled={EnableAutoLogin}, Username={AutoLoginUsername}");

                if (MainWindow.Instance.IsVisible)
                    MessageBox.Show(MainWindow.Instance,
						(string)Application.Current.FindResource("MsgAutoLoginSettingsSuccess"),
                        (string)Application.Current.FindResource("MsgSuccess"),
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                if(MainWindow.Instance.IsVisible)
                    MessageBox.Show(MainWindow.Instance,
						string.Format((string)Application.Current.FindResource("MsgAutoLoginSettingsError"), ex.Message),
                        (string) Application.Current.FindResource("MsgError"),
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
            }
        }

        public void InitializeProperties()
        {
            _isSysytemLocked = Properties.Settings.Default.IsSystemLocked;
            _blackBackground = Properties.Settings.Default.BlackBackground;
            _hideDesktopIcons = Properties.Settings.Default.HideDesktopIcons;
            _hideTaskbar = Properties.Settings.Default.HideTaskbar;
            _disableSettingsApp = Properties.Settings.Default.DisableSettingsApp;
            _disableTaskManager = Properties.Settings.Default.DisableTaskManager;
            _disableHardwareAcceleration = Properties.Settings.Default.DisableHardwareAcceleration;
            _disableRemoteDesktop = Properties.Settings.Default.DisableRemoteDesktop;
            _disableCommandPrompt = Properties.Settings.Default.DisableCommandPrompt;
            _disablePowerShell = Properties.Settings.Default.DisablePowerShell;
            _disableRegistryEditor = Properties.Settings.Default.DisableRegistryEditor;
            _disableAdministrator = Properties.Settings.Default.DisableAdministrator;
            _enableAutoLogin = Properties.Settings.Default.EnableAutoLogin;
            _autoLoginUsername = Properties.Settings.Default.AutoLoginUsername;
            _autoLoginPassword = Properties.Settings.Default.AutoLoginPassword;
            _disableSmartAppControl = Properties.Settings.Default.DisableSmartAppControl;
            if (!_disableSmartAppControl && Properties.Settings.Default.DisableSmartScreen)
            {
                _disableSmartAppControl = true;
                Properties.Settings.Default.DisableSmartAppControl = true;
                Properties.Settings.Default.DisableSmartScreen = false;
                Properties.Settings.Default.Save();
            }
            _disableUAC = Properties.Settings.Default.DisableUAC;
            _disableWindowsUpdate = Properties.Settings.Default.DisableWindowsUpdate;
        }

        public void ApplyDesktopSettings()
        {
            try
            {
                if (BlackBackground)
                    DesktopManager.SetWallpaper("#000000");
                else
                    DesktopManager.RestoreDefaultWallpaper();
    
                DesktopManager.SetDesktopIconsVisibility(!HideDesktopIcons);
    
                if(MainWindow.Instance.IsVisible)
                    MessageBox.Show(MainWindow.Instance,
						(string)Application.Current.FindResource("MsgDesktopSettingsSuccess"),
                        (string)Application.Current.FindResource("MsgSuccess"),
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                if (MainWindow.Instance.IsVisible)
                    MessageBox.Show(MainWindow.Instance,
						string.Format((string)Application.Current.FindResource("MsgDesktopSettingsError"), ex.Message),
                        (string)Application.Current.FindResource("MsgError"),
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
            }
        }
    
        public void ApplySystemControls()
        {
            try
            {
                if (!SystemUtilities.IsRunningAsAdmin())
                {
                    if (MainWindow.Instance.IsVisible)
                        MessageBox.Show(MainWindow.Instance,
							(string)Application.Current.FindResource("MsgAdminRequired"),
                            (string)Application.Current.FindResource("MsgWarning"),
                            MessageBoxButton.OK,
                            MessageBoxImage.Warning);
                    return;
                }
    
                SystemManager.SetTaskbarEnabled(!HideTaskbar);
                SystemManager.SetSettingsAppEnabled(!DisableSettingsApp);
                SystemManager.SetTaskManagerEnabled(!DisableTaskManager);
                SystemManager.SetHardwareAccelerationEnabled(!DisableHardwareAcceleration);
                SystemManager.SetRemoteDesktopEnabled(!DisableRemoteDesktop);
                SystemManager.SetWindowsUpdateEnabled(!DisableWindowsUpdate);

                if (MainWindow.Instance.IsVisible)
                    MessageBox.Show(MainWindow.Instance,
					(string)Application.Current.FindResource("MsgSystemControlsSuccess"),
                    (string)Application.Current.FindResource("MsgSuccess"),
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                if (MainWindow.Instance.IsVisible)
                    MessageBox.Show(MainWindow.Instance,
						string.Format((string)Application.Current.FindResource("MsgSystemControlsError"), ex.Message),
                        (string)Application.Current.FindResource("MsgError"),
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
            }
        }
    
        public void UpdateAutoLoginPassword()
        {
            if (AutoLoginPasswordBox != null)
				AutoLoginPassword = AutoLoginPasswordBox.Password;
		}

        private bool CanApplyProtectedSettings()
        {
            return !IsApplyingProtectedSettings;
        }

        private bool EnsureAdminPrivileges()
        {
            if (SystemUtilities.IsRunningAsAdmin())
            {
                return true;
            }

            if (MainWindow.Instance.IsVisible)
            {
                MessageBox.Show(MainWindow.Instance,
                    (string)Application.Current.FindResource("MsgAdminRequired"),
                    (string)Application.Current.FindResource("MsgWarning"),
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }

            return false;
        }

        private async Task<bool> RunProtectedSettingsOperationAsync(Action operation, Action onBeforeRun = null)
        {
            if (IsApplyingProtectedSettings)
            {
                return false;
            }

            onBeforeRun?.Invoke();

            IsApplyingProtectedSettings = true;
            Mouse.OverrideCursor = Cursors.Wait;

            try
            {
                await Task.Run(operation);
                return true;
            }
            finally
            {
                Mouse.OverrideCursor = null;
                IsApplyingProtectedSettings = false;
            }
        }

        public async Task ApplySecuritySettingsAsync()
        {
            if (!EnsureAdminPrivileges())
            {
                return;
            }

            try
            {
                bool completed = await RunProtectedSettingsOperationAsync(() => ApplySecuritySettings(showMessages: false));
                if (!completed)
                {
                    return;
                }

                if (MainWindow.Instance.IsVisible)
                {
                    MessageBox.Show(MainWindow.Instance,
                        (string)Application.Current.FindResource("MsgSecuritySuccess"),
                        (string)Application.Current.FindResource("MsgSuccess"),
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                if (MainWindow.Instance.IsVisible)
                {
                    MessageBox.Show(MainWindow.Instance,
                        string.Format((string)Application.Current.FindResource("MsgSecurityError"), ex.Message),
                        (string)Application.Current.FindResource("MsgError"),
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
                }
            }
        }

        public async Task ApplySignageSettingsAsync()
        {
            if (!EnsureAdminPrivileges())
            {
                return;
            }

            try
            {
                bool completed = await RunProtectedSettingsOperationAsync(
                    () => ApplySignageSettings(showMessages: false),
                    () => DisableSmartAppControl = true);
                if (!completed)
                {
                    return;
                }

                if (MainWindow.Instance.IsVisible)
                {
                    MessageBox.Show(MainWindow.Instance,
                        (string)Application.Current.FindResource("MsgSignageSettingsSuccess"),
                        (string)Application.Current.FindResource("MsgSuccess"),
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                if (MainWindow.Instance.IsVisible)
                {
                    MessageBox.Show(MainWindow.Instance,
                        string.Format((string)Application.Current.FindResource("MsgSignageSettingsError"), ex.Message),
                        (string)Application.Current.FindResource("MsgError"),
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
                }
            }
        }
    
        public void ApplySecuritySettings()
        {
            ApplySecuritySettings(showMessages: true);
        }

        private void ApplySecuritySettings(bool showMessages)
        {
            try
            {
                if (!SystemUtilities.IsRunningAsAdmin())
                {
                    if (showMessages && MainWindow.Instance.IsVisible)
                        MessageBox.Show(MainWindow.Instance,
							(string)Application.Current.FindResource("MsgAdminRequired"),
                            (string)Application.Current.FindResource("MsgWarning"),
                            MessageBoxButton.OK, 
                            MessageBoxImage.Warning);
                    return;
                }
        
                // 다른 보안 설정 적용
                SystemManager.SetCommandPromptEnabled(!DisableCommandPrompt);
                SystemManager.SetPowerShellEnabled(!DisablePowerShell);
                SecurityManager.SetRegistryEditorEnabled(!DisableRegistryEditor);
                SecurityManager.SetAdministratorAccountEnabled(!DisableAdministrator);
                SecurityManager.SetSmartScreenEnabled(!DisableSmartAppControl);
                SecurityManager.SetSmartAppControlEnabled(!DisableSmartAppControl);
                SecurityManager.SetUACEnabled(!DisableUAC);
                                    
                if (showMessages && MainWindow.Instance.IsVisible)
                    MessageBox.Show(MainWindow.Instance,
						(string)Application.Current.FindResource("MsgSecuritySuccess"),
                        (string)Application.Current.FindResource("MsgSuccess"),
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                if (showMessages && MainWindow.Instance.IsVisible)
                {
                    MessageBox.Show(MainWindow.Instance,
					    string.Format((string)Application.Current.FindResource("MsgSecurityError"), ex.Message),
                        (string)Application.Current.FindResource("MsgError"),
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
                }
                else
                {
                    throw;
                }
            }
        }
        public void ApplySignageSettings()
        {
            ApplySignageSettings(showMessages: true);
        }

        private void ApplySignageSettings(bool showMessages)
        {
            try
            {
                if (!SystemUtilities.IsRunningAsAdmin())
                {
                    if (showMessages && MainWindow.Instance.IsVisible)
                    {
                        MessageBox.Show(MainWindow.Instance,
						(string)Application.Current.FindResource("MsgAdminRequired"),
                        (string)Application.Current.FindResource("MsgWarning"),
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                    }

                    return;
                }
    
                SystemManager.ApplySignageSettings();
                DisableSmartAppControl = true;
                SecurityManager.SetSmartScreenEnabled(false);
                SecurityManager.SetSmartAppControlEnabled(false);
                
                if (showMessages && MainWindow.Instance.IsVisible)
                    MessageBox.Show(MainWindow.Instance,
						(string)Application.Current.FindResource("MsgSignageSettingsSuccess"),
                    (string)Application.Current.FindResource("MsgSuccess"),
                    MessageBoxButton.OK, 
                    MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                if (showMessages && MainWindow.Instance.IsVisible)
                {
                    MessageBox.Show(MainWindow.Instance,
					    string.Format((string)Application.Current.FindResource("MsgSignageSettingsError"), ex.Message),
                        (string)Application.Current.FindResource("MsgError"),
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
                }
                else
                {
                    throw;
                }
            }
        }

        public void EnablePreventHack()
        {
            Application.Current.Dispatcher.Invoke(new Action(() =>
            {
                // Apply all settings
                BlackBackground = true;
                HideDesktopIcons = true;
                HideTaskbar = true;
                DisableSmartAppControl = true;
                DisableUAC = true;
                DisableSettingsApp = true;
                DisableTaskManager = true;
                DisableHardwareAcceleration = false;
                DisableRemoteDesktop = true;
                DisableWindowsUpdate = true;
                DisableCommandPrompt = true;
                DisablePowerShell = true;
                DisableRegistryEditor = true;
                DisableAdministrator = true;
                IsSystemLocked = true;
            }));

            ApplyDesktopSettings();
            ApplySystemControls();
            ApplySecuritySettings();
            
            // 가상 데스크톱 및 태스크 뷰 비활성화
            try
            {
                SystemManager.SetVirtualDesktopAndTaskViewEnabled(false);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"가상 데스크톱 및 태스크 뷰 비활성화 중 오류 발생: {ex.Message}");
            }
        }

        public void DisablePreventHack()
        {
            Application.Current.Dispatcher.Invoke(new Action(() =>
            {
                // Reset all settings to false
                BlackBackground = false;
                HideDesktopIcons = false;
                HideTaskbar = false;
                DisableSettingsApp = false;
                DisableTaskManager = false;
                DisableHardwareAcceleration = false;
                DisableRemoteDesktop = false;
                DisableWindowsUpdate = false;
                DisableCommandPrompt = false;
                DisablePowerShell = false;
                DisableRegistryEditor = false;
                DisableAdministrator = false;
                DisableSmartAppControl = false;
                DisableUAC = false;
                IsSystemLocked = false;
            }));

            ApplyDesktopSettings();
            ApplySystemControls();
            ApplySecuritySettings();
            
            // 가상 데스크톱 및 태스크 뷰 활성화
            try
            {
                SystemManager.SetVirtualDesktopAndTaskViewEnabled(true);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"가상 데스크톱 및 태스크 뷰 활성화 중 오류 발생: {ex.Message}");
            }
        }
            
        public void RestartAsAdmin()
        {
            try
            {
                // Release single instance lock first
                SingleInstanceManager.Release();
    
                // Give some time for the lock to be fully released
                Thread.Sleep(500);
    
                ProcessStartInfo startInfo = new ProcessStartInfo
                {
                    FileName = Process.GetCurrentProcess().MainModule.FileName,
                    UseShellExecute = true,
                    Verb = "runas" // This requests elevation
                };
    
                Process.Start(startInfo);
    
                // Exit the current process after starting the new one
                Application.Current.Dispatcher.Invoke(new Action(() =>
                {
                    Application.Current.Shutdown();
                }));
            }
            catch (Exception)
            {
                // User cancelled the UAC prompt or other error occurred
                SingleInstanceManager.Initialize(); // Reinitialize if restart failed
            }
        }
    
        #region INotifyPropertyChanged Implementation
    
        public event PropertyChangedEventHandler PropertyChanged;
    
        protected virtual void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion
    }
}
