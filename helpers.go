package engine

import (
	"fmt"
	"strings"
)

// findTech looks up a technique from the Catalog by FullID.
func findTech(id string) TechDef {
	for _, t := range Catalog {
		if t.FullID() == id {
			return t
		}
	}
	// Return a placeholder if not found
	return TechDef{ID: id, Name: id, Severity: SevMed}
}

// printTechHeader prints a formatted technique header box.
func printTechHeader(id, name string, sev Severity) {
	sevStr, sevCol := sevLabel(sev)
	fmt.Println()
	fmt.Printf("  %s %s  %s  %s\n",
		C(CBBlu, "┌─"),
		C(CBCyn, id),
		C(CBold, name),
		C(sevCol, "["+sevStr+"]"))
	fmt.Printf("  %s\n", C(CBBlu, "│"))
}

func sevLabel(sev Severity) (string, string) {
	switch sev {
	case SevCrit:
		return "CRITICAL", CBRed
	case SevHigh:
		return "HIGH", CRed
	case SevMed:
		return "MEDIUM", CYel
	case SevLow:
		return "LOW", CGreen
	default:
		return "INFO", CCyan
	}
}

// printIOCs prints the IOC list for a technique.
func printIOCs(iocs []string) {
	if len(iocs) == 0 {
		return
	}
	BlankLine()
	fmt.Println("  " + C(CBYel, "Indicators of Compromise (IOCs):"))
	for _, ioc := range iocs {
		fmt.Printf("    %s %s\n", C(CYel, "◆"), ioc)
	}
}

// printDetection prints detection guidance.
func printDetection(hints []string) {
	if len(hints) == 0 {
		return
	}
	BlankLine()
	fmt.Println("  " + C(CBGrn, "Detection Opportunities:"))
	for _, h := range hints {
		fmt.Printf("    %s %s\n", C(CGreen, "✓"), h)
	}
	BlankLine()
}

// printCodeBlock prints code with a border.
func printCodeBlock(code string) {
	lines := strings.Split(strings.TrimRight(code, "\n"), "\n")
	fmt.Println("  " + C(CGray, "  "+strings.Repeat("─", 62)))
	for _, line := range lines {
		fmt.Printf("  %s %s\n", C(CGray, " "), C(CCyan, line))
	}
	fmt.Println("  " + C(CGray, "  "+strings.Repeat("─", 62)))
	BlankLine()
}

// TechSummaryTable prints the full technique catalog formatted as a table.
func TechSummaryTable(filterPlatform string) {
	fmt.Println()
	fmt.Printf("  %-12s %-35s %-14s %-10s %s\n",
		C(CBBlu, "TECH ID"),
		C(CBBlu, "NAME"),
		C(CBBlu, "PLATFORM"),
		C(CBBlu, "SEVERITY"),
		C(CBBlu, "FAMILY"))
	fmt.Println("  " + C(CGray, strings.Repeat("─", 90)))

	for i, t := range Catalog {
		// Filter by platform if requested
		if filterPlatform != "" && filterPlatform != "all" {
			match := false
			for _, p := range t.Platforms {
				if p == filterPlatform || p == "cross" {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}

		_, sevCol := sevLabel(t.Severity)
		platStr := strings.Join(t.Platforms, "/")
		if len(platStr) > 13 {
			platStr = platStr[:13]
		}
		nameStr := t.Name
		if len(nameStr) > 33 {
			nameStr = nameStr[:33]
		}

		numStr := fmt.Sprintf("%2d", i+1)
		fmt.Printf("  %s %-12s %-35s %-14s %s  %s\n",
			C(CGray, numStr+"."),
			C(CBCyn, t.FullID()),
			nameStr,
			C(CGray, platStr),
			C(sevCol, string(t.Severity)),
			C(CGray, t.Family))
	}
	fmt.Println()
}

// TechDetail prints full detail for a single technique.
func TechDetail(t TechDef) {
	_, sevCol := sevLabel(t.Severity)
	BlankLine()
	Divider()
	fmt.Printf("  %s   %s\n", C(CBCyn, t.FullID()), C(CBold, t.Name))
	fmt.Printf("  %s\n", C(sevCol, "Severity: "+string(t.Severity)))
	fmt.Printf("  %s\n", C(CGray, "Family:   "+t.Family))
	fmt.Printf("  %s\n", C(CGray, "Platform: "+strings.Join(t.Platforms, ", ")))
	BlankLine()
	fmt.Printf("  %s\n", C(CBBlu, "Description:"))
	fmt.Printf("  %s\n", t.Description)
	BlankLine()
	if len(t.IOCHints) > 0 {
		fmt.Printf("  %s\n", C(CBYel, "IOC Hints:"))
		for _, ioc := range t.IOCHints {
			fmt.Printf("    %s %s\n", C(CYel, "◆"), ioc)
		}
		BlankLine()
	}
	if len(t.DetectHints) > 0 {
		fmt.Printf("  %s\n", C(CBGrn, "Detection:"))
		for _, d := range t.DetectHints {
			fmt.Printf("    %s %s\n", C(CGreen, "✓"), d)
		}
	}
	Divider()
	BlankLine()
}
