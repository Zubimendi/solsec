package reporter

import (
	"fmt"
	"os"
	"text/template"
	"time"

	"github.com/Zubimendi/solsec/internal/parser"
	"github.com/Zubimendi/solsec/internal/scorer"
)

type HTMLReporter struct{}

func (r *HTMLReporter) Name() string { return "html" }

func (r *HTMLReporter) Write(report *parser.AnalysisReport, score int, outputPath string) error {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"severityClass": func(s parser.Severity) string {
			switch s {
			case parser.SeverityCritical:
				return "critical"
			case parser.SeverityHigh:
				return "high"
			case parser.SeverityMedium:
				return "medium"
			case parser.SeverityLow:
				return "low"
			default:
				return "info"
			}
		},
		"gradeClass": func(g string) string {
			switch g {
			case "A":
				return "grade-a"
			case "B":
				return "grade-b"
			case "C":
				return "grade-c"
			case "D", "F":
				return "grade-f"
			default:
				return ""
			}
		},
		"now": func() string {
			return time.Now().Format("2006-01-02 15:04:05 UTC")
		},
		"grade":   scorer.Grade,
		"verdict": scorer.Verdict,
		"join": func(lines []int) string {
			result := ""
			for i, l := range lines {
				if i > 0 {
					result += ", "
				}
				result += fmt.Sprintf("%d", l)
			}
			return result
		},
	}).Parse(htmlTemplate)

	if err != nil {
		return fmt.Errorf("parsing HTML template: %w", err)
	}

	f, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return fmt.Errorf("creating HTML report: %w", err)
	}
	defer f.Close()

	return tmpl.Execute(f, struct {
		Report  *parser.AnalysisReport
		Score   int
		Grade   string
		Verdict string
	}{
		Report:  report,
		Score:   score,
		Grade:   scorer.Grade(score),
		Verdict: scorer.Verdict(score),
	})
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>solsec Report — {{.Report.Target}}</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e;
    --critical: #f85149; --high: #ff7b72; --medium: #e3b341; --low: #3fb950; --info: #58a6ff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: var(--bg); color: var(--text); padding: 2rem; line-height: 1.6; }
  .container { max-width: 1100px; margin: 0 auto; }
  header { border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }
  h1 { font-size: 1.5rem; font-weight: 700; }
  .meta { color: var(--muted); font-size: 0.875rem; margin-top: 0.25rem; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }
  .stat-card .count { font-size: 2rem; font-weight: 700; }
  .stat-card .label { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
  .critical { color: var(--critical); } .high { color: var(--high); }
  .medium { color: var(--medium); } .low { color: var(--low); } .info { color: var(--info); }
  .grade-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
    padding: 1.5rem; margin-bottom: 2rem; display: flex; align-items: center; gap: 1.5rem; }
  .grade-letter { font-size: 4rem; font-weight: 900; line-height: 1; }
  .grade-a { color: var(--low); } .grade-b { color: #57ab5a; } .grade-c { color: var(--medium); }
  .grade-f { color: var(--critical); }
  .verdict-text { font-size: 1.1rem; }
  .score-bar { height: 8px; background: var(--border); border-radius: 4px; margin-top: 0.5rem; overflow: hidden; }
  .score-fill { height: 100%; border-radius: 4px; background: var(--critical); transition: width 0.3s; }
  .findings-table { width: 100%; border-collapse: collapse; }
  .findings-table th { text-align: left; padding: 0.75rem 1rem; background: var(--surface);
    border-bottom: 1px solid var(--border); font-size: 0.8rem; text-transform: uppercase;
    letter-spacing: 0.05em; color: var(--muted); }
  .findings-table td { padding: 1rem; border-bottom: 1px solid var(--border); vertical-align: top; font-size: 0.9rem; }
  .findings-table tr:hover { background: var(--surface); }
  .badge { display: inline-block; padding: 0.2em 0.6em; border-radius: 4px; font-size: 0.75rem;
    font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; }
  .badge-critical { background: rgba(248,81,73,0.15); color: var(--critical); border: 1px solid var(--critical); }
  .badge-high { background: rgba(255,123,114,0.15); color: var(--high); border: 1px solid var(--high); }
  .badge-medium { background: rgba(227,179,65,0.15); color: var(--medium); border: 1px solid var(--medium); }
  .badge-low { background: rgba(63,185,80,0.15); color: var(--low); border: 1px solid var(--low); }
  .badge-info { background: rgba(88,166,255,0.15); color: var(--info); border: 1px solid var(--info); }
  .remediation { background: rgba(88,166,255,0.05); border-left: 3px solid var(--info);
    padding: 0.5rem 0.75rem; margin-top: 0.5rem; font-size: 0.85rem; border-radius: 0 4px 4px 0; }
  .swc-ref { font-size: 0.75rem; color: var(--muted); }
  code { font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.85em;
    background: var(--surface); padding: 0.1em 0.4em; border-radius: 3px; }
  .no-findings { text-align: center; padding: 3rem; color: var(--muted); }
  .source-badge { font-size: 0.7rem; padding: 0.1em 0.4em; border-radius: 3px;
    background: var(--border); color: var(--muted); }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>🔐 solsec — Smart Contract Security Report</h1>
    <div class="meta">Target: <code>{{.Report.Target}}</code> &nbsp;|&nbsp; Generated: {{now}}</div>
  </header>

  <div class="grade-card">
    <div class="grade-letter {{.Grade | gradeClass}}">{{.Grade}}</div>
    <div>
      <div class="verdict-text">{{.Verdict}}</div>
      <div class="score-bar" style="width: 200px; margin-top: 0.75rem;">
        <div class="score-fill" style="width: {{.Score}}%;"></div>
      </div>
      <div style="font-size:0.8rem; color:var(--muted); margin-top:0.25rem;">Risk score: {{.Score}}/100</div>
    </div>
  </div>

  <div class="summary-grid">
    <div class="stat-card"><div class="count">{{.Report.Summary.Total}}</div><div class="label">Total</div></div>
    <div class="stat-card"><div class="count critical">{{.Report.Summary.Critical}}</div><div class="label">Critical</div></div>
    <div class="stat-card"><div class="count high">{{.Report.Summary.High}}</div><div class="label">High</div></div>
    <div class="stat-card"><div class="count medium">{{.Report.Summary.Medium}}</div><div class="label">Medium</div></div>
    <div class="stat-card"><div class="count low">{{.Report.Summary.Low}}</div><div class="label">Low</div></div>
    <div class="stat-card"><div class="count info">{{.Report.Summary.Informational}}</div><div class="label">Info</div></div>
  </div>

  {{if eq .Report.Summary.Total 0}}
  <div class="no-findings">
    <div style="font-size: 3rem; margin-bottom: 1rem;">✅</div>
    <div>No findings detected. Review manually before mainnet deployment.</div>
  </div>
  {{else}}
  <table class="findings-table">
    <thead>
      <tr>
        <th>Severity</th><th>ID</th><th>Title</th><th>Location</th><th>Source</th>
      </tr>
    </thead>
    <tbody>
    {{range .Report.Findings}}
    <tr>
      <td><span class="badge badge-{{.Severity | severityClass}}">{{.Severity}}</span></td>
      <td><code>{{.ID}}</code></td>
      <td>
        <strong>{{.Title}}</strong>
        <div style="color:var(--muted); font-size:0.85rem; margin-top:0.25rem;">{{.Description}}</div>
        {{if .Remediation}}
        <div class="remediation">💡 {{.Remediation}}</div>
        {{end}}
        {{if .SWCRef}}<div class="swc-ref" style="margin-top:0.4rem;">Ref: {{.SWCRef}}</div>{{end}}
      </td>
      <td>
        {{if .File}}<code>{{.File}}</code>{{end}}
        {{if .Lines}}<br><span style="color:var(--muted);">Line{{if gt (len .Lines) 1}}s{{end}}: {{join .Lines}}</span>{{end}}
      </td>
      <td><span class="source-badge">{{.Source}}</span></td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{end}}

  <footer style="margin-top:2rem; padding-top:1rem; border-top:1px solid var(--border);
    font-size:0.8rem; color:var(--muted); text-align:center;">
    Generated by <strong>solsec v1.0.0</strong> — Smart Contract Static Analyzer<br>
    This report is a tool-assisted analysis. Always conduct a manual audit before mainnet deployment.
  </footer>
</div>
</body>
</html>`