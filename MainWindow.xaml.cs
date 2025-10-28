using Microsoft.Win32;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System;
using System.Linq;
using System.Reflection;

namespace MDE_Monitoring_App
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            Icon = new BitmapImage(new Uri("pack://application:,,,/Resources/microsoft_defender_icon.png"));
            if (DataContext is null)
                DataContext = new MainViewModel();
        }

        private async void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            if (DataContext is MainViewModel vm)
                await vm.RefreshDataAsync();
        }

        private async Task RefreshDeviceControlPoliciesAsync()
        {
            if (DataContext is MainViewModel vm)
            {
                await Task.Run(() =>
                {
                    var status = vm.DeviceControlPolicyStatus;
                });
            }
        }

        private void ClearFirewallFilter_Click(object sender, RoutedEventArgs e)
        {
            if (DataContext is MainViewModel vm)
            {
                vm.FirewallFilterText = string.Empty;
            }
        }

        private async void ExportPdf_Click(object sender, RoutedEventArgs e)
        {
            if (DataContext is not MainViewModel vm) return;

            var dlg = new SaveFileDialog
            {
                Title = "Export Security Report",
                Filter = "PDF Files|*.pdf",
                FileName = $"EndpointSecurityReport_{DateTime.Now:yyyyMMdd_HHmm}.pdf"
            };
            if (dlg.ShowDialog(this) != true)
                return;

            Mouse.OverrideCursor = Cursors.Wait;
            try
            {
                var ok = await vm.ExportPdfAsync(dlg.FileName);
                MessageBox.Show(this,
                    ok ? "PDF export complete." : "Export failed.",
                    "Export",
                    MessageBoxButton.OK,
                    ok ? MessageBoxImage.Information : MessageBoxImage.Error);
            }
            finally
            {
                Mouse.OverrideCursor = null;
            }
        }

        private void PolicyRulesGrid_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (sender is not DataGrid grid) return;

            var dep = (DependencyObject)e.OriginalSource;

            while (dep != null && dep is not DataGridRow && dep is not DataGridColumnHeader)
                dep = VisualTreeHelper.GetParent(dep);

            if (dep is DataGridColumnHeader) return;
            if (dep is not DataGridRow row) return;

            if (row.DetailsVisibility == Visibility.Visible)
            {
                row.DetailsVisibility = Visibility.Collapsed;
                e.Handled = true;
            }
            else
            {
                foreach (var item in grid.Items)
                {
                    if (grid.ItemContainerGenerator.ContainerFromItem(item) is DataGridRow r &&
                        r != row &&
                        r.DetailsVisibility == Visibility.Visible)
                    {
                        r.DetailsVisibility = Visibility.Collapsed;
                    }
                }

                row.DetailsVisibility = Visibility.Visible;
                row.IsSelected = true;
                e.Handled = true;
            }
        }

        private void LogsDataGrid_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (sender is not DataGrid grid) return;

            var dep = (DependencyObject)e.OriginalSource;

            while (dep != null && dep is not DataGridRow && dep is not DataGridColumnHeader)
                dep = VisualTreeHelper.GetParent(dep);

            if (dep is DataGridColumnHeader) return;
            if (dep is not DataGridRow row) return;

            if (row.DetailsVisibility == Visibility.Visible)
            {
                row.DetailsVisibility = Visibility.Collapsed;
                e.Handled = true;
            }
            else
            {
                foreach (var item in grid.Items)
                {
                    if (grid.ItemContainerGenerator.ContainerFromItem(item) is DataGridRow r &&
                        r != row &&
                        r.DetailsVisibility == Visibility.Visible)
                    {
                        r.DetailsVisibility = Visibility.Collapsed;
                    }
                }
                row.DetailsVisibility = Visibility.Visible;
                row.IsSelected = true;
                e.Handled = true;
            }
        }

        private void AppControlDataGrid_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (sender is not DataGrid grid) return;

            var dep = (DependencyObject)e.OriginalSource;
            while (dep != null && dep is not DataGridRow && dep is not DataGridColumnHeader)
                dep = VisualTreeHelper.GetParent(dep);

            if (dep is DataGridColumnHeader) return;
            if (dep is not DataGridRow row) return;

            if (row.DetailsVisibility == Visibility.Visible)
            {
                row.DetailsVisibility = Visibility.Collapsed;
                e.Handled = true;
            }
            else
            {
                foreach (var item in grid.Items)
                {
                    if (grid.ItemContainerGenerator.ContainerFromItem(item) is DataGridRow r &&
                        r != row &&
                        r.DetailsVisibility == Visibility.Visible)
                    {
                        r.DetailsVisibility = Visibility.Collapsed;
                    }
                }
                row.DetailsVisibility = Visibility.Visible;
                row.IsSelected = true;
                e.Handled = true;
            }
        }

        protected override void OnContentRendered(EventArgs e)
        {
            base.OnContentRendered(e);
            var args = Environment.GetCommandLineArgs();
            if (args.Skip(1).Any(a => a is "--help" or "/?"))
            {
                MessageBox.Show(CommandLineOptions.Usage, "Usage",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void FileExit_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }

        // CHANGED: Pass remote context into AdvancedNetworkingWindow so netsh runs remotely
        private void AdvancedNetworking_Click(object sender, RoutedEventArgs e)
        {
            AdvancedNetworkingWindow wnd;
            if (DataContext is MainViewModel vm)
            {
                wnd = new AdvancedNetworkingWindow(vm.TargetMachine, vm.UsePsExec, vm.UsePsExec ? vm.PsExecPath : null)
                {
                    Owner = this
                };
            }
            else
            {
                wnd = new AdvancedNetworkingWindow { Owner = this };
            }
            wnd.ShowDialog();
        }

        private void HelpUsage_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show(this, CommandLineOptions.Usage, "Usage", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void HelpAbout_Click(object sender, RoutedEventArgs e)
        {
            var asm = Assembly.GetExecutingAssembly().GetName();
            MessageBoxResult messageBoxResult = MessageBox.Show(this,
                $"MDE Monitoring App\nVersion: {asm.Version}\nStrong Name Token: {string.Concat(asm.GetPublicKeyToken().Select(b => b.ToString("x2")))}",
                "About", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
}