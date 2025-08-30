using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MDEMonitor.Models
{
    public class LogEntry
    {
        public DateTime Time { get; set; }
        public required string Level { get; set; }
        public required string Message { get; set; }
    }
}

