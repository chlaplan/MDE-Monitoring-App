using System;
using System.Text.RegularExpressions;
using MDE_Monitoring_App.Models;

namespace MDE_Monitoring_App.Services
{
    public static class DeviceControlLogParser
    {
        private static readonly Regex LogRegex = new(
            @"DoDevicePresenceNotification:.*?InstancePathId\[(.*?)\].*?VID\[(.*?)\].*?PID\[(.*?)\].*?CurrentGrantedAccess\[(.*?)\].*?CurrentDeniedAccess\[(.*?)\]",
            RegexOptions.Compiled | RegexOptions.CultureInvariant);

        public static DeviceControlEvent? ParseLine(string line)
        {
            var m = LogRegex.Match(line);
            if (!m.Success) return null;

            return new DeviceControlEvent
            {
                Timestamp = DateTime.Now,
                InstancePathId = m.Groups[1].Value,
                VID = m.Groups[2].Value,
                PID = m.Groups[3].Value,
                GrantedAccess = m.Groups[4].Value,
                DeniedAccess = m.Groups[5].Value
            };
        }
    }
}
