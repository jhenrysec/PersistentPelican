package engine

// HTML and CSV report generation.

import (
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/template"
	"time"
)

// ExportCSV writes all session results to a CSV file.
func ExportCSV(sess *Session, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	w.Write([]string{"Timestamp", "TechID", "TechName", "Status", "Severity",
		"Platform", "Location", "Notes", "IOCs", "Detection"})

	sess.mu.Lock()
	defer sess.mu.Unlock()
	for _, r := range sess.Results {
		w.Write([]string{
			r.Timestamp.Format(time.RFC3339),
			r.TechID, r.TechName, string(r.Status),
			string(r.Severity), r.Platform, r.Location, r.Notes,
			strings.Join(r.IOCs, " | "),
			strings.Join(r.Detection, " | "),
		})
	}
	return nil
}

// ExportHTML generates a dark-mode professional HTML report.
func ExportHTML(sess *Session, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	funcMap := template.FuncMap{
		"statusColor": func(s Status) string {
			switch s {
			case StatusOK:
				return "#22c55e"
			case StatusSim:
				return "#a855f7"
			case StatusFail:
				return "#ef4444"
			default:
				return "#6b7280"
			}
		},
		"sevColor": func(s Severity) string {
			switch s {
			case SevCrit:
				return "#dc2626"
			case SevHigh:
				return "#ea580c"
			case SevMed:
				return "#d97706"
			case SevLow:
				return "#65a30d"
			default:
				return "#6b7280"
			}
		},
		"upper":   strings.ToUpper,
		"elapsed": func() string { return time.Since(sess.StartTime).Round(time.Second).String() },
		"join":    strings.Join,
		"countStatus": func(s Status) int {
			n := 0
			for _, r := range sess.Results {
				if r.Status == s {
					n++
				}
			}
			return n
		},
		"countSev": func(s Severity) int {
			n := 0
			for _, r := range sess.Results {
				if r.Severity == s {
					n++
				}
			}
			return n
		},
		"groupBySev": func() map[string][]Result {
			g := map[string][]Result{}
			for _, r := range sess.Results {
				key := string(r.Severity)
				g[key] = append(g[key], r)
			}
			return g
		},
	}

	tmpl, err := template.New("html").Funcs(funcMap).Parse(htmlTmpl)
	if err != nil {
		return err
	}

	type data struct {
		Session  *Session
		Now      string
		Tactics  []string
	}
	tactics := uniqueTactics(sess.Results)
	return tmpl.Execute(f, data{Session: sess, Now: time.Now().Format("2006-01-02 15:04:05"), Tactics: tactics})
}

func uniqueTactics(results []Result) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range results {
		if !seen[r.TechID] {
			seen[r.TechID] = true
			out = append(out, r.TechID)
		}
	}
	sort.Strings(out)
	return out
}

// PrintSessionSummary prints the post-run terminal summary.
func PrintSessionSummary(sess *Session) {
	ok, sim, fail, skip := sess.Counts()
	sess.mu.Lock()
	results := make([]Result, len(sess.Results))
	copy(results, sess.Results)
	sess.mu.Unlock()

	fmt.Println()
	fmt.Println(C(CBBlu, "  ╔══════════════════════════════════════════════════════════════╗"))
	fmt.Println(C(CBBlu, "  ║") + "  " + Bold("SESSION SUMMARY — TA0003 Persistence") + C(CBBlu, "                    ║"))
	fmt.Println(C(CBBlu, "  ╚══════════════════════════════════════════════════════════════╝"))
	fmt.Println()
	fmt.Printf("  %-28s %s\n", "Session Start:", sess.StartTime.Format("2006-01-02 15:04:05"))
	fmt.Printf("  %-28s %s\n", "Duration:", time.Since(sess.StartTime).Round(time.Second))
	fmt.Printf("  %-28s %s\n", "Simulation Mode:", fmt.Sprintf("%v", sess.SimMode))
	fmt.Printf("  %-28s %d techniques\n\n", "Total Executed:", len(results))

	Divider()
	fmt.Printf("  %s %-10s  %s %-10s  %s %-10s  %s %-10s\n",
		C(CBGrn, "✓"), fmt.Sprintf("Success: %d", ok),
		C(CMag, "~"), fmt.Sprintf("Simulated: %d", sim),
		C(CBRed, "✗"), fmt.Sprintf("Failed: %d", fail),
		C(CGray, "–"), fmt.Sprintf("Skipped: %d", skip))
	Divider()
	fmt.Println()

	// Results table
	fmt.Printf("  %-12s %-32s %-10s %-10s %s\n",
		C(CBBlu, "TECH ID"), C(CBBlu, "NAME"), C(CBBlu, "STATUS"), C(CBBlu, "SEVERITY"), C(CBBlu, "LOCATION"))
	fmt.Println("  " + C(CGray, strings.Repeat("─", 90)))

	for _, r := range results {
		_, sevCol := sevLabel(r.Severity)
		statusStr, statusCol := statusLabel(r.Status)
		nameStr := r.TechName
		if len(nameStr) > 30 {
			nameStr = nameStr[:30]
		}
		locStr := r.Location
		if len(locStr) > 32 {
			locStr = "..." + locStr[len(locStr)-29:]
		}
		fmt.Printf("  %-12s %-32s %s  %s  %s\n",
			C(CBCyn, r.TechID),
			nameStr,
			C(statusCol, fmt.Sprintf("%-10s", statusStr)),
			C(sevCol, fmt.Sprintf("%-10s", string(r.Severity))),
			C(CGray, locStr))
	}
	fmt.Println()
}

func statusLabel(s Status) (string, string) {
	switch s {
	case StatusOK:
		return "SUCCESS", CBGrn
	case StatusSim:
		return "SIMULATED", CMag
	case StatusFail:
		return "FAILED", CBRed
	default:
		return "SKIPPED", CGray
	}
}

// ── HTML template ─────────────────────────────────────────────

const htmlTmpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Persistence Toolkit — TA0003 Report</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--border:#21262d;--text:#c9d1d9;--muted:#8b949e;
      --blue:#58a6ff;--green:#3fb950;--red:#f85149;--orange:#d29922;--purple:#bc8cff;
      --cyan:#39d353;--yellow:#e3b341;--code:#1c2128}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.7}
.wrap{max-width:1440px;margin:0 auto;padding:28px}
.hero{background:linear-gradient(135deg,#0d1117 0%,#161b22 100%);border:1px solid var(--border);border-radius:12px;padding:32px;margin-bottom:28px}
h1{font-size:2.2rem;font-weight:700;color:var(--blue);margin-bottom:6px}
.subtitle{color:var(--muted);font-size:.95rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:28px}
.stat{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:18px;text-align:center}
.stat-n{font-size:2.4rem;font-weight:700;line-height:1}
.stat-l{color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.08em;margin-top:4px}
table{width:100%;border-collapse:collapse;margin-bottom:28px}
th{background:var(--panel);padding:10px 14px;text-align:left;font-size:.75rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);border-bottom:2px solid var(--border);white-space:nowrap}
td{padding:10px 14px;border-bottom:1px solid var(--border);vertical-align:top;font-size:.85rem}
tr:hover td{background:var(--panel)}
.badge{display:inline-block;padding:2px 9px;border-radius:4px;font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;background:rgba(0,0,0,.3)}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:20px;margin-bottom:18px}
.card-title{font-size:1rem;font-weight:600;color:var(--blue);margin-bottom:12px}
.mono{font-family:'Cascadia Code','Courier New',monospace;font-size:.82rem}
.ioc-list,.det-list{list-style:none;padding:0;margin:0}
.ioc-list li::before{content:"◆ ";color:var(--yellow)}
.det-list li::before{content:"✓ ";color:var(--green)}
.ioc-list li,.det-list li{margin:3px 0;font-size:.83rem}
footer{text-align:center;color:var(--muted);font-size:.78rem;padding:24px 0;border-top:1px solid var(--border);margin-top:28px}
.sev-critical{color:#f85149} .sev-high{color:#d29922} .sev-medium{color:#e3b341} .sev-low{color:#3fb950} .sev-info{color:#8b949e}
.st-success{color:#3fb950} .st-simulated{color:#bc8cff} .st-failed{color:#f85149} .st-skipped{color:#8b949e}
.section-header{font-size:1.15rem;font-weight:600;color:var(--text);margin:28px 0 14px;padding-bottom:6px;border-bottom:2px solid var(--border)}
</style>
</head>
<body>
<div class="wrap">

<div class="hero">
  <h1>MITRE ATT&amp;CK Persistence Toolkit</h1>
  <div class="subtitle">
    Tactic: TA0003 – Persistence &nbsp;·&nbsp; Generated: {{.Now}} &nbsp;·&nbsp; Simulation Mode: {{.Session.SimMode}}
  </div>
</div>

<div class="grid">
  <div class="stat"><div class="stat-n" style="color:var(--blue)">{{len .Session.Results}}</div><div class="stat-l">Techniques Run</div></div>
  <div class="stat"><div class="stat-n" style="color:var(--green)">{{countStatus "success"}}</div><div class="stat-l">Successful</div></div>
  <div class="stat"><div class="stat-n" style="color:var(--purple)">{{countStatus "simulated"}}</div><div class="stat-l">Simulated</div></div>
  <div class="stat"><div class="stat-n" style="color:var(--red)">{{countSev "critical"}}</div><div class="stat-l">Critical Severity</div></div>
  <div class="stat"><div class="stat-n" style="color:var(--orange)">{{countSev "high"}}</div><div class="stat-l">High Severity</div></div>
</div>

<div class="section-header">Execution Results</div>
<table>
  <thead>
    <tr><th>#</th><th>Technique ID</th><th>Name</th><th>Status</th><th>Severity</th><th>Platform</th><th>Location / Artifact</th></tr>
  </thead>
  <tbody>
  {{range $i, $r := .Session.Results}}
  <tr>
    <td class="mono" style="color:var(--muted)">{{$i}}</td>
    <td class="mono" style="color:var(--blue)">{{$r.TechID}}</td>
    <td style="font-weight:500">{{$r.TechName}}</td>
    <td><span class="badge st-{{$r.Status}}" style="color:{{statusColor $r.Status}}">{{upper (string($r.Status))}}</span></td>
    <td><span class="badge sev-{{$r.Severity}}" style="color:{{sevColor $r.Severity}}">{{upper (string($r.Severity))}}</span></td>
    <td class="mono" style="color:var(--muted)">{{$r.Platform}}</td>
    <td class="mono" style="font-size:.78rem;color:var(--muted);word-break:break-all">{{$r.Location}}</td>
  </tr>
  {{end}}
  </tbody>
</table>

<div class="section-header">Technique Detail — IOCs &amp; Detection</div>
{{range .Session.Results}}
<div class="card">
  <div class="card-title">
    <span style="color:var(--blue)" class="mono">{{.TechID}}</span> &nbsp;
    {{.TechName}} &nbsp;
    <span class="badge sev-{{.Severity}}" style="color:{{sevColor .Severity}}">{{upper (string(.Severity))}}</span>
    &nbsp;
    <span class="badge st-{{.Status}}" style="color:{{statusColor .Status}}">{{upper (string(.Status))}}</span>
  </div>
  {{if .Location}}<div style="color:var(--muted);font-size:.82rem;margin-bottom:8px">📁 {{.Location}}</div>{{end}}
  {{if .Notes}}<div style="color:var(--orange);font-size:.82rem;margin-bottom:8px">📝 {{.Notes}}</div>{{end}}

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:10px">
    {{if .IOCs}}
    <div>
      <div style="font-size:.72rem;text-transform:uppercase;letter-spacing:.08em;color:var(--yellow);margin-bottom:6px">Indicators of Compromise</div>
      <ul class="ioc-list">{{range .IOCs}}<li>{{.}}</li>{{end}}</ul>
    </div>
    {{end}}
    {{if .Detection}}
    <div>
      <div style="font-size:.72rem;text-transform:uppercase;letter-spacing:.08em;color:var(--green);margin-bottom:6px">Detection Opportunities</div>
      <ul class="det-list">{{range .Detection}}<li>{{.}}</li>{{end}}</ul>
    </div>
    {{end}}
  </div>
</div>
{{end}}

<footer>MITRE ATT&amp;CK Persistence Toolkit &nbsp;·&nbsp; TA0003 &nbsp;·&nbsp; FOR AUTHORIZED TESTING AND EDUCATIONAL USE ONLY</footer>
</div>
</body>
</html>`

// string is needed in template for Status/Severity types
func init() {
	_ = fmt.Sprintf // suppress import
}
