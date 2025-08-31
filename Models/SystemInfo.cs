using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace MDE_Monitoring_App.Models
{
    public class SystemInfo : INotifyPropertyChanged
    {
        private string _currentUser = string.Empty;
        private string _machineName = string.Empty;
        private string _ipAddress = string.Empty;
        private string _joinType = string.Empty;

        public string CurrentUser { get => _currentUser; set => Set(ref _currentUser, value); }
        public string MachineName { get => _machineName; set => Set(ref _machineName, value); }
        public string IPAddress { get => _ipAddress; set => Set(ref _ipAddress, value); }
        public string JoinType { get => _joinType; set => Set(ref _joinType, value); }

        public event PropertyChangedEventHandler? PropertyChanged;
        private void Set<T>(ref T field, T value, [CallerMemberName] string? prop = null)
        {
            if (!Equals(field, value))
            {
                field = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(prop));
            }
        }
    }
}