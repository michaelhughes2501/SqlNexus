using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace SqlNexus.McpServer
{
    /// <summary>
    /// Three-layer PII scrubber applied to all MCP tool outputs before returning to the agent.
    ///
    /// Layer 1 — Regex  : GUIDs, IP addresses, computer names (WIN-* / DESKTOP-*)
    /// Layer 2 — Presidio: NLP-based entity recognition (names, emails, phone numbers, etc.)
    ///                      Invoked via a Python subprocess; skipped gracefully if Python /
    ///                      Presidio is not available on the host.
    /// Layer 3 — URL allowlist: URLs not in the approved list are replaced with &lt;Scrubbed_URL&gt;
    /// </summary>
    public static class PiiScrubber
    {
        // ── Layer 1: Regex rules ────────────────────────────────────────────────
        private static readonly (Regex Pattern, string Replacement)[] s_regexRules =
        {
            // GUIDs  e.g. 6ba7b810-9dad-11d1-80b4-00c04fd430c8
            (new Regex(
                @"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
                RegexOptions.IgnoreCase | RegexOptions.Compiled),
             "<GUID>"),

            // IPv4 addresses  e.g. 192.168.1.100
            (new Regex(
                @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
                RegexOptions.Compiled),
             "<IP>"),

            // Windows auto-generated machine names  e.g. WIN-ABC1234, DESKTOP-XY98765
            (new Regex(
                @"\b(win-|desktop-)[a-z0-9]{7,15}\b",
                RegexOptions.IgnoreCase | RegexOptions.Compiled),
             "<COMPUTER>"),
        };

        // ── Layer 3: URL allowlist ──────────────────────────────────────────────
        private static readonly Regex s_urlPattern =
            new Regex(@"https?://[^\s""'<>]+", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private static readonly string[] s_urlAllowlist =
        {
            "https://stackoverflow.com/questions",
            "https://techcommunity.microsoft.com",
            "https://learn.microsoft.com/",
            "https://kb.databricks.com/en_us/azure",
            "https://issues.apache.org/jira/projects",
            "https://www.databricks.com/blog",
            "https://spark.apache.org/documentation",
            "https://blog.fabric.microsoft.com/en-us/blog",
            "https://powerbi.microsoft.com/en-us/blog",
            "https://blog.crossjoin.co.uk",
            "https://www.sqlbi.com/articles",
            "https://pbidax.wordpress.com/author/jwang8888",
            "https://dax.tips",
            "https://www.microsoft.com",
        };

        // ── Layer 2: Inline Presidio Python script ──────────────────────────────
        // Written once to %TEMP%\pii_scrub_presidio.py on first use.
        // Reads text from stdin, writes scrubbed text to stdout.
        private const string PresidioPythonScript = @"
import sys
import spacy
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import SpacyNlpEngine
from presidio_anonymizer import AnonymizerEngine

class LoadedSpacyNlpEngine(SpacyNlpEngine):
    def __init__(self, loaded_spacy_model):
        super().__init__()
        self.nlp = {'en': loaded_spacy_model}

nlp = spacy.load('en_core_web_lg')
nlp_engine = LoadedSpacyNlpEngine(loaded_spacy_model=nlp)
analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
anonymizer = AnonymizerEngine()

text = sys.stdin.read()
results = analyzer.analyze(text=text, language='en')
scrubbed = anonymizer.anonymize(text=text, analyzer_results=results).text
sys.stdout.write(scrubbed)
";

        private static readonly string s_scriptPath =
            Path.Combine(Path.GetTempPath(), "pii_scrub_presidio.py");

        // ── Public entry point ──────────────────────────────────────────────────

        /// <summary>
        /// Scrubs PII from <paramref name="text"/> through all three layers and returns the result.
        /// If the Presidio layer is unavailable (Python not found, missing packages, etc.)
        /// layers 1 and 3 still apply and a warning is written to stderr.
        /// </summary>
        public static string Scrub(string text)
        {
            if (string.IsNullOrEmpty(text))
                return text;

            text = ApplyRegex(text);        // Layer 1
            text = ApplyPresidio(text);     // Layer 2
            text = ApplyUrlAllowlist(text); // Layer 3

            return text;
        }

        // ── Layer implementations ───────────────────────────────────────────────

        private static string ApplyRegex(string text)
        {
            foreach (var (pattern, replacement) in s_regexRules)
                text = pattern.Replace(text, replacement);
            return text;
        }

        private static string ApplyPresidio(string text)
        {
            try
            {
                // Write the helper script on first call
                if (!File.Exists(s_scriptPath))
                    File.WriteAllText(s_scriptPath, PresidioPythonScript, Encoding.UTF8);

                var psi = new ProcessStartInfo
                {
                    FileName               = "python",
                    Arguments              = $"\"{s_scriptPath}\"",
                    UseShellExecute        = false,
                    RedirectStandardInput  = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true,
                    StandardOutputEncoding = Encoding.UTF8,
                    CreateNoWindow         = true
                };

                using (var process = Process.Start(psi))
                {
                    if (process == null)
                    {
                        Console.Error.WriteLine("[PiiScrubber] Presidio layer skipped: Python process could not be started.");
                        return text;
                    }

                    // Write as UTF-8 explicitly (StandardInputEncoding not available on .NET 4.8)
                    using (var stdinWriter = new StreamWriter(process.StandardInput.BaseStream, Encoding.UTF8))
                        stdinWriter.Write(text);

                    string scrubbed = process.StandardOutput.ReadToEnd();
                    string errors   = process.StandardError.ReadToEnd();

                    bool exited = process.WaitForExit(30_000); // 30-second timeout
                    if (!exited)
                    {
                        process.Kill();
                        Console.Error.WriteLine("[PiiScrubber] Presidio layer timed out after 30 s; skipping.");
                        return text;
                    }

                    if (!string.IsNullOrWhiteSpace(errors))
                        Console.Error.WriteLine($"[PiiScrubber] Presidio stderr: {errors}");

                    return string.IsNullOrEmpty(scrubbed) ? text : scrubbed;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[PiiScrubber] Presidio layer skipped ({ex.GetType().Name}): {ex.Message}");
                return text; // graceful fallback — layers 1 and 3 still apply
            }
        }

        private static string ApplyUrlAllowlist(string text)
        {
            return s_urlPattern.Replace(text, match =>
            {
                string url = match.Value;
                foreach (string allowed in s_urlAllowlist)
                {
                    if (url.StartsWith(allowed, StringComparison.OrdinalIgnoreCase))
                        return url;
                }
                return "<Scrubbed_URL>";
            });
        }
    }
}
