package proxy

import (
	"fmt"
	"os/exec"
	"runtime"
)

// InjectCA installs the CA certificate into the system trust store.
// Requires elevated privileges on most platforms.
func InjectCA(certPath string) error {
	switch runtime.GOOS {
	case "darwin":
		return injectDarwin(certPath)
	case "linux":
		return injectLinux(certPath)
	case "windows":
		return injectWindows(certPath)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// RemoveCA removes the CA certificate from the system trust store.
func RemoveCA(certPath string) error {
	switch runtime.GOOS {
	case "darwin":
		return removeDarwin(certPath)
	case "linux":
		return removeLinux(certPath)
	case "windows":
		return removeWindows(certPath)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

func injectDarwin(certPath string) error {
	cmd := exec.Command("security", "add-trusted-cert", "-d", "-r", "trustRoot",
		"-k", "/Library/Keychains/System.keychain", certPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		printManualInstructions("macOS", certPath)
		return fmt.Errorf("macOS trust injection failed (requires sudo): %s: %w", string(out), err)
	}
	fmt.Println("CA certificate trusted on macOS.")
	return nil
}

func injectLinux(certPath string) error {
	dest := "/usr/local/share/ca-certificates/phoenix-firewall-ca.crt"
	cpCmd := exec.Command("cp", certPath, dest)
	if out, err := cpCmd.CombinedOutput(); err != nil {
		printManualInstructions("Linux", certPath)
		return fmt.Errorf("copy CA cert failed (requires sudo): %s: %w", string(out), err)
	}
	updateCmd := exec.Command("update-ca-certificates")
	if out, err := updateCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("update-ca-certificates failed: %s: %w", string(out), err)
	}
	fmt.Println("CA certificate trusted on Linux.")
	return nil
}

func injectWindows(certPath string) error {
	cmd := exec.Command("certutil", "-addstore", "-user", "Root", certPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		printManualInstructions("Windows", certPath)
		return fmt.Errorf("certutil failed: %s: %w", string(out), err)
	}
	fmt.Println("CA certificate trusted on Windows.")
	return nil
}

func removeDarwin(certPath string) error {
	cmd := exec.Command("security", "remove-trusted-cert", "-d", certPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("macOS trust removal failed: %s: %w", string(out), err)
	}
	return nil
}

func removeLinux(_ string) error {
	cmd := exec.Command("rm", "-f", "/usr/local/share/ca-certificates/phoenix-firewall-ca.crt")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("remove CA cert failed: %s: %w", string(out), err)
	}
	updateCmd := exec.Command("update-ca-certificates", "--fresh")
	if out, err := updateCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("update-ca-certificates failed: %s: %w", string(out), err)
	}
	return nil
}

func removeWindows(certPath string) error {
	cmd := exec.Command("certutil", "-delstore", "-user", "Root", certPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("certutil removal failed: %s: %w", string(out), err)
	}
	return nil
}

func printManualInstructions(platform, certPath string) {
	fmt.Println("\n=== Manual CA Trust Instructions ===")
	fmt.Printf("Platform: %s\n", platform)
	fmt.Printf("CA cert:  %s\n\n", certPath)
	switch platform {
	case "macOS":
		fmt.Println("Run with sudo:")
		fmt.Printf("  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s\n", certPath)
	case "Linux":
		fmt.Println("Run with sudo:")
		fmt.Printf("  sudo cp %s /usr/local/share/ca-certificates/phoenix-firewall-ca.crt\n", certPath)
		fmt.Println("  sudo update-ca-certificates")
	case "Windows":
		fmt.Println("Run as Administrator:")
		fmt.Printf("  certutil -addstore -user Root %s\n", certPath)
	}
	fmt.Println("====================================")
}
