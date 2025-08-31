using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using MDE_Monitoring_App.Models;

namespace MDE_Monitoring_App.Services
{
    public class LatestDefenderVersionService
    {
        private const string UpdatePageUrl = "https://www.microsoft.com/en-us/wdsi/defenderupdates";

        // Primary patterns
        private static readonly Regex PlatformRegex =
            new(@"Platform\s*version:\s*</td>\s*<td[^>]*>\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        private static readonly Regex EngineRegex =
            new(@"Engine\s*version:\s*</td>\s*<td[^>]*>\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        private static readonly Regex SigRegex =
            new(@"Security\s+intelligence\s+version:\s*</td>\s*<td[^>]*>\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        // Fallback patterns (in case markup changes to ‘>Platform version<’ spans or strong tags)
        private static readonly Regex PlatformFallback =
            new(@"Platform[^<]*version[^0-9]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        private static readonly Regex EngineFallback =
            new(@"Engine[^<]*version[^0-9]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        private static readonly Regex SigFallback =
            new(@"Security[^<]*intelligence[^<]*version[^0-9]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public async Task<(LatestDefenderVersions? versions, LatestFetchState state, string? error)> GetLatestAsync()
        {
            try
            {
                using var http = new HttpClient
                {
                    Timeout = TimeSpan.FromSeconds(15)
                };
                // Headers help avoid localized/JS-different responses
                http.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) MDEMonitor/1.0");
                http.DefaultRequestHeaders.AcceptLanguage.ParseAdd("en-US,en;q=0.7");
                http.DefaultRequestHeaders.CacheControl = new CacheControlHeaderValue { NoCache = true };

                var html = await http.GetStringAsync(UpdatePageUrl).ConfigureAwait(false);

                string platform = MatchAny(PlatformRegex, PlatformFallback, html);
                string engine = MatchAny(EngineRegex, EngineFallback, html);
                string sig = MatchAny(SigRegex, SigFallback, html);

                if (string.IsNullOrWhiteSpace(platform) &&
                    string.IsNullOrWhiteSpace(engine) &&
                    string.IsNullOrWhiteSpace(sig))
                {
                    return (null, LatestFetchState.Failed, "Regex did not match update site");
                }

                return (new LatestDefenderVersions
                {
                    PlatformVersion = platform,
                    EngineVersion = engine,
                    SecurityIntelligenceVersion = sig
                }, LatestFetchState.Success, null);
            }
            catch (Exception ex)
            {
                return (null, LatestFetchState.Failed, ex.Message);
            }
        }

        private static string MatchAny(Regex primary, Regex fallback, string html)
        {
            var m = primary.Match(html);
            if (m.Success) return m.Groups[1].Value.Trim();
            m = fallback.Match(html);
            return m.Success ? m.Groups[1].Value.Trim() : string.Empty;
        }
    }
}