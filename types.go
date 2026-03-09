// Package engine – MITRE ATT&CK TA0003 Persistence Toolkit
// All techniques are demonstrated for authorized lab use only.
package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ── ANSI palette ──────────────────────────────────────────────
const (
	CR     = "\033[0m"
	CBold  = "\033[1m"
	CDim   = "\033[2m"
	CRed   = "\033[0;31m"
	CGreen = "\033[0;32m"
	CYel   = "\033[0;33m"
	CBlue  = "\033[0;34m"
	CMag   = "\033[0;35m"
	CCyan  = "\033[0;36m"
	CGray  = "\033[2;37m"
	CBRed  = "\033[1;31m"
	CBGrn  = "\033[1;32m"
	CBBlu  = "\033[1;34m"
	CBCyn  = "\033[1;36m"
	CBMag  = "\033[1;35m"
	CBYel  = "\033[1;33m"
)

func C(clr, s string) string { return clr + s + CR }
func Bold(s string) string   { return CBold + s + CR }

func OK(msg string)         { fmt.Printf("  %s %s\n", C(CBGrn, "[+]"), msg) }
func Warn(msg string)       { fmt.Printf("  %s %s\n", C(CBYel, "[!]"), msg) }
func Fail(msg string)       { fmt.Printf("  %s %s\n", C(CBRed, "[-]"), msg) }
func Info(msg string)       { fmt.Printf("  %s %s\n", C(CCyan, "[*]"), msg) }
func Sim(msg string)        { fmt.Printf("  %s %s\n", C(CMag, "[~]"), msg) }
func KV(k, v string)        { fmt.Printf("    %-32s %s\n", C(CGray, k+":"), C(CBCyn, v)) }
func Divider()              { fmt.Println("  " + C(CGray, strings.Repeat("─", 66))) }
func BlankLine()            { fmt.Println() }

func SectionHeader(title, mitre string) {
	fmt.Println()
	fmt.Println(C(CBBlu, "  ╔══════════════════════════════════════════════════════════════╗"))
	fmt.Printf(C(CBBlu, "  ║")+" %-61s"+C(CBBlu, "║")+"\n", Bold(title))
	if mitre != "" {
		fmt.Printf(C(CBBlu, "  ║")+"  %s%-57s"+C(CBBlu, "║")+"\n",
			C(CMag, "MITRE: "), C(CMag, mitre))
	}
	fmt.Println(C(CBBlu, "  ╚══════════════════════════════════════════════════════════════╝"))
	fmt.Println()
}

// ── Platform helpers ──────────────────────────────────────────
var (
	IsWindows = runtime.GOOS == "windows"
	IsLinux   = runtime.GOOS == "linux"
	IsMacOS   = runtime.GOOS == "darwin"
	IsUnix    = IsLinux || IsMacOS
)

func Platform() string { return runtime.GOOS }
func HomeDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	if IsWindows {
		return os.Getenv("USERPROFILE")
	}
	return os.Getenv("HOME")
}

// ── Result types ──────────────────────────────────────────────
type Status string

const (
	StatusOK  Status = "success"
	StatusSim Status = "simulated"
	StatusFail Status = "failed"
	StatusSkip Status = "skipped"
)

type Severity string

const (
	SevCrit   Severity = "critical"
	SevHigh   Severity = "high"
	SevMed    Severity = "medium"
	SevLow    Severity = "low"
	SevInfo   Severity = "info"
)

type Result struct {
	Timestamp time.Time         `json:"timestamp"`
	TechID    string            `json:"technique_id"`
	TechName  string            `json:"technique_name"`
	Status    Status            `json:"status"`
	Severity  Severity          `json:"severity"`
	Platform  string            `json:"platform"`
	Location  string            `json:"location,omitempty"`
	Payload   string            `json:"payload,omitempty"`
	IOCs      []string          `json:"iocs,omitempty"`
	Detection []string          `json:"detection_notes,omitempty"`
	Notes     string            `json:"notes,omitempty"`
	Details   map[string]string `json:"details,omitempty"`
	Simulated bool              `json:"simulated,omitempty"`
}

// ── Session ───────────────────────────────────────────────────
type Session struct {
	mu        sync.Mutex
	StartTime time.Time `json:"start_time"`
	SimMode   bool      `json:"simulation_mode"`
	Results   []Result  `json:"results"`
}

func NewSession(sim bool) *Session {
	return &Session{StartTime: time.Now(), SimMode: sim}
}

func (s *Session) Add(r Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.Timestamp = time.Now()
	r.Platform = Platform()
	s.Results = append(s.Results, r)
}

func (s *Session) SaveJSON(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	type wrap struct {
		Start    string   `json:"start_time"`
		Elapsed  string   `json:"elapsed"`
		SimMode  bool     `json:"simulation_mode"`
		Results  []Result `json:"results"`
	}
	w := wrap{
		Start:   s.StartTime.Format(time.RFC3339),
		Elapsed: time.Since(s.StartTime).Round(time.Second).String(),
		SimMode: s.SimMode,
		Results: s.Results,
	}
	b, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}

func (s *Session) Counts() (ok, sim, fail, skip int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.Results {
		switch r.Status {
		case StatusOK:
			ok++
		case StatusSim:
			sim++
		case StatusFail:
			fail++
		case StatusSkip:
			skip++
		}
	}
	return
}

// ── Technique catalog entry ───────────────────────────────────
type TechDef struct {
	ID          string
	SubID       string // e.g. ".001"
	Name        string
	Family      string   // parent technique name
	Platforms   []string // "windows","linux","darwin","cross"
	Severity    Severity
	Description string
	DetectHints []string
	IOCHints    []string
}

func (t TechDef) FullID() string {
	if t.SubID != "" {
		return t.ID + t.SubID
	}
	return t.ID
}

func (t TechDef) SupportsPlatform(p string) bool {
	for _, pl := range t.Platforms {
		if pl == p || pl == "cross" {
			return true
		}
	}
	return false
}

// Catalog is the full list of implemented persistence techniques.
var Catalog = []TechDef{
	// ── Windows ───────────────────────────────────────────────
	{ID: "T1547", SubID: ".001", Name: "Registry Run Keys", Family: "Boot/Logon Autostart",
		Platforms: []string{"windows"}, Severity: SevHigh,
		Description: "Writes payload path to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run (or HKLM equivalent). Executes at every user logon without UAC.",
		DetectHints: []string{"Sysmon EID 13 – RegistryEvent (SetValue)", "Windows Security Event 4657", "Autoruns.exe baseline delta", "EDR registry write alert on Run keys"},
		IOCHints:    []string{"New value under HKCU/HKLM …\\Run", "Unsigned binary path in Run value", "Explorer.exe child process matching Run value"},
	},
	{ID: "T1547", SubID: ".001b", Name: "Startup Folder", Family: "Boot/Logon Autostart",
		Platforms: []string{"windows"}, Severity: SevHigh,
		Description: "Drops a shortcut (.lnk) or script to %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup. Executes for every user logon.",
		DetectHints: []string{"Sysmon EID 11 – FileCreate in Startup path", "Autoruns.exe Logon tab", "Explorer.exe spawning unexpected child"},
		IOCHints:    []string{"New .lnk/.bat/.vbs in Startup folder", "LNK file pointing to temp or unusual path"},
	},
	{ID: "T1543", SubID: ".003", Name: "Windows Service", Family: "Create/Modify System Process",
		Platforms: []string{"windows"}, Severity: SevCrit,
		Description: "Creates a Windows service pointing to a payload binary. Starts automatically at boot, runs as SYSTEM. Survives reboots.",
		DetectHints: []string{"System Event 7045 – New Service Installed", "Sysmon EID 12/13 on HKLM\\…\\Services", "sc.exe / PowerShell New-Service execution", "Unsigned service binary"},
		IOCHints:    []string{"New service key in HKLM\\SYSTEM\\CurrentControlSet\\Services", "Service binary in temp/appdata path", "Service start type = BOOT_START or AUTO_START"},
	},
	{ID: "T1053", SubID: ".005", Name: "Scheduled Task", Family: "Scheduled Task/Job",
		Platforms: []string{"windows"}, Severity: SevHigh,
		Description: "Registers a Windows Scheduled Task via schtasks.exe or COM (ITaskService) with ONLOGON, DAILY, or ONIDLE triggers.",
		DetectHints: []string{"Security Event 4698 – Task Created", "Sysmon EID 1 – schtasks.exe", "Task XML written to C:\\Windows\\System32\\Tasks\\", "TaskScheduler Operational log"},
		IOCHints:    []string{"New task XML in Tasks directory", "Encoded command in task Action", "Hidden or system-named task"},
	},
	{ID: "T1546", SubID: ".003", Name: "WMI Event Subscription", Family: "Event Triggered Execution",
		Platforms: []string{"windows"}, Severity: SevCrit,
		Description: "Creates permanent WMI subscriptions: __EventFilter (trigger) + CommandLineEventConsumer (action) + __FilterToConsumerBinding. Survives reboots, no files needed.",
		DetectHints: []string{"Sysmon EID 19/20/21 – WMI Filter/Consumer/Binding", "WMI-Activity/Operational log", "Get-WMIObject __EventFilter", "EDR WMI subscription alert"},
		IOCHints:    []string{"__EventFilter object in ROOT\\subscription namespace", "CommandLineEventConsumer with encoded command", "WMI-Activity log entry 5857"},
	},
	{ID: "T1547", SubID: ".004", Name: "Winlogon Helper DLL", Family: "Boot/Logon Autostart",
		Platforms: []string{"windows"}, Severity: SevCrit,
		Description: "Modifies HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon Userinit or Shell value. Payload runs as SYSTEM at every logon.",
		DetectHints: []string{"Autoruns.exe – Winlogon tab", "Sysmon EID 7 – winlogon.exe loading unexpected DLL", "Registry baseline on Winlogon key"},
		IOCHints:    []string{"Userinit value appended with extra binary", "Shell value pointing to non-explorer.exe binary"},
	},
	{ID: "T1547", SubID: ".005", Name: "Security Support Provider (SSP)", Family: "Boot/Logon Autostart",
		Platforms: []string{"windows"}, Severity: SevCrit,
		Description: "Registers a DLL as an SSP/AP in HKLM\\…\\Lsa\\Security Packages. LSASS loads it at boot — DLL receives plaintext credentials on every interactive logon.",
		DetectHints: []string{"Windows Event 4611 – Trusted Logon Process", "Sysmon EID 7 – lsass.exe loading unknown DLL", "Autoruns.exe LSA Providers tab"},
		IOCHints:    []string{"New DLL name in Security Packages multi-string value", "DLL in System32 without Microsoft signature"},
	},
	{ID: "T1037", SubID: ".001", Name: "Logon Script", Family: "Boot/Logon Initialization Scripts",
		Platforms: []string{"windows"}, Severity: SevMed,
		Description: "Sets HKCU\\Environment\\UserInitMprLogonScript to a batch/script path. Executes at user logon in user context via userinit.exe.",
		DetectHints: []string{"Sysmon EID 13 – UserInitMprLogonScript", "Process creation audit at logon", "Autoruns.exe"},
		IOCHints:    []string{"UserInitMprLogonScript value present in HKCU\\Environment", "Script at unusual path"},
	},
	{ID: "T1574", SubID: ".001", Name: "DLL Search Order Hijacking", Family: "Hijack Execution Flow",
		Platforms: []string{"windows"}, Severity: SevHigh,
		Description: "Places a malicious DLL with the same name as a system DLL in an application's directory, which is searched before System32. Proxy DLL template provided.",
		DetectHints: []string{"Sysmon EID 7 – DLL loaded from non-System32 path", "AppLocker / WDAC DLL rules", "Process Monitor – Path Not Found then success"},
		IOCHints:    []string{"DLL in application folder matching System32 DLL name", "Unsigned DLL in trusted process memory"},
	},
	{ID: "T1546", SubID: ".001", Name: "File Association Hijack", Family: "Event Triggered Execution",
		Platforms: []string{"windows"}, Severity: SevMed,
		Description: "Modifies HKCU\\Software\\Classes to intercept common file types (.txt, .html). Opening any matching file triggers payload execution.",
		DetectHints: []string{"Sysmon EID 13 – HKCU\\Software\\Classes", "Autoruns.exe – File Associations tab", "Registry auditing on Classes key"},
		IOCHints:    []string{"Unexpected command in shell\\open\\command", "UserChoice hijack for common extension"},
	},
	{ID: "T1547", SubID: ".009", Name: "Shortcut Modification", Family: "Boot/Logon Autostart",
		Platforms: []string{"windows"}, Severity: SevMed,
		Description: "Replaces or hijacks an existing .lnk shortcut (Desktop, Taskbar) to execute payload before the legitimate application.",
		DetectHints: []string{"Sysmon EID 11 – LNK file write", "LNK parser baseline", "Process creation showing dual execution chain"},
		IOCHints:    []string{"LNK TargetPath pointing to cmd.exe or unusual binary", "Two-stage process tree from shortcut"},
	},
	{ID: "T1546", SubID: ".015", Name: "COM Object Hijacking", Family: "Event Triggered Execution",
		Platforms: []string{"windows"}, Severity: SevHigh,
		Description: "Registers a rogue COM server under HKCU for a CLSID that exists in HKLM. When trusted processes instantiate the COM object, the attacker payload loads instead.",
		DetectHints: []string{"Autoruns.exe – COM/Hijacks tab", "Sysmon EID 7/13 – COM CLSID registry", "Registry monitoring HKCU\\Software\\Classes\\CLSID"},
		IOCHints:    []string{"CLSID under HKCU overriding HKLM", "DLL/EXE registered as InprocServer32 in HKCU"},
	},
	{ID: "T1547", SubID: ".014", Name: "Active Setup", Family: "Boot/Logon Autostart",
		Platforms: []string{"windows"}, Severity: SevHigh,
		Description: "Adds a key to HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\. Windows runs the StubPath command once per user at logon.",
		DetectHints: []string{"Sysmon EID 13 – Active Setup registry key", "Autoruns.exe – Active Setup tab", "Process creation from Active Setup context"},
		IOCHints:    []string{"New GUID key under Active Setup\\Installed Components", "StubPath pointing to unusual binary"},
	},
	{ID: "T1542", SubID: ".001", Name: "System Firmware (UEFI) – Demo", Family: "Pre-OS Boot",
		Platforms: []string{"windows", "linux"}, Severity: SevCrit,
		Description: "Simulates UEFI/firmware persistence concepts. Real implantation requires physical access and vendor tools — this module demonstrates detection of UEFI threat indicators.",
		DetectHints: []string{"Secure Boot enforcement (no unsigned EFI binaries)", "EFI partition file integrity monitoring", "TPM attestation / measured boot", "Chipsec UEFI scanner"},
		IOCHints:    []string{"Unexpected .efi file in EFI System Partition", "Modified NVRAM Boot variables", "UEFI variable write without OS permission"},
	},
	{ID: "T1547", SubID: ".010", Name: "Port Monitors", Family: "Boot/Logon Autostart",
		Platforms: []string{"windows"}, Severity: SevHigh,
		Description: "Registers a malicious DLL as a print port monitor via HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors. Loaded by spoolsv.exe (SYSTEM) at boot.",
		DetectHints: []string{"Registry key under Print\\Monitors", "Sysmon EID 7 – spoolsv.exe loading DLL", "Autoruns.exe – Print Monitors tab"},
		IOCHints:    []string{"New key under Print\\Monitors with Driver value", "Unsigned DLL loaded by spoolsv.exe"},
	},
	{ID: "T1547", SubID: ".012", Name: "Print Processor", Family: "Boot/Logon Autostart",
		Platforms: []string{"windows"}, Severity: SevHigh,
		Description: "Registers a rogue DLL as a print processor under HKLM\\…\\Print\\Environments. Spoolsv.exe loads it as SYSTEM at startup.",
		DetectHints: []string{"Registry write to Print\\Environments\\…\\Print Processors", "Sysmon EID 7 – spoolsv.exe", "Windows Event 316"},
		IOCHints:    []string{"New print processor DLL not from Microsoft", "DLL loaded by spoolsv from non-System32 path"},
	},
	// ── Linux / macOS ─────────────────────────────────────────
	{ID: "T1543", SubID: ".002", Name: "Systemd Service", Family: "Create/Modify System Process",
		Platforms: []string{"linux"}, Severity: SevHigh,
		Description: "Drops a .service unit file to /etc/systemd/system/ or ~/.config/systemd/user/. Enables with systemctl so it starts at boot or user login.",
		DetectHints: []string{"File integrity monitoring on /etc/systemd/system/", "auditd write events on systemd paths", "systemctl list-units --state=enabled baseline"},
		IOCHints:    []string{"New .service file with ExecStart to unusual binary", "Service with WantedBy=multi-user.target"},
	},
	{ID: "T1053", SubID: ".003", Name: "Cron Job", Family: "Scheduled Task/Job",
		Platforms: []string{"linux", "darwin"}, Severity: SevHigh,
		Description: "Adds payload to /etc/cron.d/, /etc/crontab, or user crontab. Executes on a schedule — from every minute to weekly.",
		DetectHints: []string{"File integrity monitoring on /etc/cron*", "auditd write events to cron paths", "OSSEC/Wazuh cron change rule"},
		IOCHints:    []string{"New file in /etc/cron.d/", "Crontab entry with curl|bash or base64 pattern", "Cron executing from /tmp or /dev/shm"},
	},
	{ID: "T1546", SubID: ".004", Name: "Unix Shell Profile", Family: "Event Triggered Execution",
		Platforms: []string{"linux", "darwin"}, Severity: SevMed,
		Description: "Appends payload to ~/.bashrc, ~/.zshrc, /etc/profile.d/, or ~/.bash_profile. Executes whenever the target user opens an interactive shell.",
		DetectHints: []string{"File integrity monitoring on shell init files", "auditd open-write events on .bashrc/.zshrc", "Baseline comparison of /etc/profile.d/"},
		IOCHints:    []string{"Base64 decode command appended to .bashrc", "curl|sh or wget|bash pattern in shell init"},
	},
	{ID: "T1037", SubID: ".004", Name: "RC / Init Script", Family: "Boot/Logon Initialization Scripts",
		Platforms: []string{"linux"}, Severity: SevHigh,
		Description: "Appends to /etc/rc.local or creates an SysV init script in /etc/init.d/ — executes as root at system boot before multi-user target.",
		DetectHints: []string{"File integrity monitoring on /etc/rc.local", "auditd write events on /etc/init.d/", "Unexpected root command at boot"},
		IOCHints:    []string{"Modified /etc/rc.local with injected command", "New init script with execute bit"},
	},
	{ID: "T1053", SubID: ".003b", Name: "Launchd Plist (macOS)", Family: "Scheduled Task/Job",
		Platforms: []string{"darwin"}, Severity: SevHigh,
		Description: "Drops a LaunchDaemon or LaunchAgent plist to /Library/LaunchDaemons/ or ~/Library/LaunchAgents/. Loaded by launchd at boot or user login.",
		DetectHints: []string{"File integrity monitoring on LaunchDaemons/Agents paths", "KnockKnock / BlockBlock macOS tools", "launchctl list baseline"},
		IOCHints:    []string{"New plist with ProgramArguments pointing to unusual binary", "RunAtLoad = true", "KeepAlive = true (watchdog behavior)"},
	},
	// ── Cross-platform ────────────────────────────────────────
	{ID: "T1098", SubID: ".004", Name: "SSH Authorized Keys", Family: "Account Manipulation",
		Platforms: []string{"linux", "darwin", "windows"}, Severity: SevHigh,
		Description: "Injects attacker's SSH public key into ~/.ssh/authorized_keys, granting passwordless persistent shell access across reboots.",
		DetectHints: []string{"File integrity monitoring on ~/.ssh/authorized_keys", "auditd write events on SSH config files", "SSH login audit – unexpected key-based login"},
		IOCHints:    []string{"New pubkey entry in authorized_keys", "authorized_keys modified outside normal provisioning"},
	},
	{ID: "T1136", SubID: ".001", Name: "Local Account Creation", Family: "Create Account",
		Platforms: []string{"windows", "linux"}, Severity: SevHigh,
		Description: "Creates a new local user account with a password and optionally adds it to privileged groups (Administrators / sudo) for guaranteed access.",
		DetectHints: []string{"Windows Event 4720/4728/4732", "auditd syscall audit – useradd/usermod", "New entry in /etc/passwd + /etc/shadow", "Unexpected account in privileged group"},
		IOCHints:    []string{"New username not in provisioning baseline", "Account added to Administrators or wheel/sudo group"},
	},
	{ID: "T1505", SubID: ".003", Name: "Web Shell", Family: "Server Software Component",
		Platforms: []string{"windows", "linux"}, Severity: SevCrit,
		Description: "Generates and deploys obfuscated PHP/ASPX/JSP web shells to web-accessible directories, enabling persistent browser-accessible command execution.",
		DetectHints: []string{"File integrity monitoring on webroot", "Web server process spawning cmd.exe/sh", "WAF rule for web shell request patterns", "Network IDS for webshell traffic"},
		IOCHints:    []string{"New .php/.aspx/.jsp file in webroot", "Web request to unusual filename", "eval(base64_decode()) or cmd.exe in web access log"},
	},
	{ID: "T1176", SubID: "", Name: "Browser Extension", Family: "Browser Extensions",
		Platforms: []string{"windows", "linux", "darwin"}, Severity: SevMed,
		Description: "Generates a malicious Chrome/Firefox extension (manifest.json + background script) with permissions for cookies, tabs, history, webRequest interception, and C2 beaconing.",
		DetectHints: []string{"Browser extension inventory audit / GPO", "Network traffic from browser to unexpected C2", "Sysmon EID 11 – file write in browser profile path", "Enterprise browser telemetry"},
		IOCHints:    []string{"Extension with broad permissions (tabs, cookies, webRequest, all_urls)", "Unpacked extension loaded from non-Store path", "Background script performing XHR to external host"},
	},
	{ID: "T1133", SubID: "", Name: "External Remote Services", Family: "External Remote Services",
		Platforms: []string{"windows", "linux"}, Severity: SevHigh,
		Description: "Demonstrates persistence via legitimate remote access services: installs a reverse SSH tunnel as a service/cron job that calls back to attacker infrastructure on a schedule.",
		DetectHints: []string{"Outbound SSH on non-standard ports", "Persistent process making SSH connections to internet IPs", "Service/cron referencing ssh -R or autossh"},
		IOCHints:    []string{"ssh -R / autossh in scheduled task or service", "SSH connection to non-corporate IP on port 443/80"},
	},
	{ID: "T1078", SubID: ".003", Name: "Valid Accounts – Local", Family: "Valid Accounts",
		Platforms: []string{"windows", "linux"}, Severity: SevHigh,
		Description: "Demonstrates credential-based persistence: modifies account passwords, enables built-in disabled accounts (Administrator, Guest), or adds NOPASSWD sudo entries.",
		DetectHints: []string{"Windows Event 4723/4738 – Account Changed", "auditd – passwd/chpasswd syscall", "/etc/sudoers NOPASSWD entry", "Built-in account re-enabled"},
		IOCHints:    []string{"Guest or Administrator account re-enabled", "NOPASSWD in /etc/sudoers.d/", "Account password changed outside provisioning window"},
	},
	{ID: "T1547", SubID: ".006", Name: "Kernel Module / Rootkit – Demo", Family: "Boot/Logon Autostart",
		Platforms: []string{"linux"}, Severity: SevCrit,
		Description: "Simulates kernel-level persistence via LKM rootkit. Demonstrates /etc/modules-load.d/ and modprobe configuration persistence vectors. No actual kernel module compiled (lab safe).",
		DetectHints: []string{"File integrity on /etc/modules-load.d/ and /etc/modprobe.d/", "auditd module load events (init_module/finit_module)", "rkhunter / chkrootkit scans", "Secure Boot signature enforcement"},
		IOCHints:    []string{"New .conf in /etc/modules-load.d/ with unusual module name", "lsmod showing unsigned module", "Module hiding from lsmod output"},
	},
}
