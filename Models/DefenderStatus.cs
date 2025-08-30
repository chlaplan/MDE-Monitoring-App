using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MDEMonitor.Models
{
    public class DefenderStatus
    {
        public string AMProductVersion { get; set; } = "";
        public string AMEngineVersion { get; set; } = "";
        public string AMRunningMode { get; set; } = "";
        public string RealTimeProtection { get; set; } = "";
        public string AntivirusSignatureAge { get; set; } = "";
        public string AntispywareSignatureAge { get; set; } = "";
        public string DeviceControlDefaultEnforcement { get; set; } = "";
        public string DeviceControlState { get; set; } = "";
    }

}


