# Task-3
Automated local vulnerability assessment using Nessus with scan results, analysis, and mitigation documentation.
# 🔍 Local Vulnerability Assessment using Nessus Essentials

This task documents the end-to-end process of performing a local vulnerability assessment using **Nessus Essentials** on a personal machine. It covers installation, scan configuration, result analysis, and documentation of critical vulnerabilities along with possible remediations.

📌 Task Objectives

- Install and configure Nessus Essentials.
- Perform a full vulnerability scan on the local machine.
- Review and analyze the scan results.
- Research and suggest simple fixes or mitigations.
- Document the most critical vulnerabilities found.

🛠️ Tools Used

- **Nessus Essentials** (Free vulnerability scanner by Tenable)
- **Operating System**: [Your OS, e.g., Windows 10 / Ubuntu 22.04]
- **Browser**: For accessing the Nessus Web UI
- **Screenshots & Documentation Tools**: Snipping Tool, Markdown Editor

📥 Installation & Configuration

1. **Download Nessus Essentials:**
   - Visit [https://www.tenable.com/products/nessus/nessus-essentials](https://www.tenable.com/products/nessus/nessus-essentials)
   - Register to receive an **activation code**.

2. **Install the Software:**
   - Follow the platform-specific installation instructions.
   - Start the Nessus service (`https://localhost:8834`) in your browser.

3. **Initial Setup:**
   - Enter the activation code.
   - Create an admin account.
   - Nessus will then download and install required plugins (this may take several minutes).

🌐 Scan Configuration

### 🗂️ 1. Host Discovery Scan

- **Objective**: Identify active hosts and open ports.
- **Steps**:
  - Create a folder named `Host Discovery`.
  - Add a new scan with type **Host Discovery**.
  - Set the **Target IP** as `127.0.0.1` (localhost).
  - Launch the scan.

### ⚙️ 2. Advanced Scan

- **Objective**: Perform an in-depth vulnerability assessment.
- **Steps**:
  - Create another folder named `Advanced Scan`.
  - Select **Advanced Scan** template.
  - Target: `127.0.0.1`
  - Enable all plugins (or leave default).
  - Launch the scan.

⏱️ Scan Duration

- Scans may take **30–60 minutes**, depending on the system performance and network services running.

📊 Scan Results

### Screenshot Samples

- **Initial Interface after Plugin Download**
- **Host Discovery Results**
- **Advanced Scan Results**
- **Vulnerability Summary by Severity (Critical, High, Medium, Low, Info)**

All screenshots are included in the `/screenshots` folder in this repository.

🔐 Critical Vulnerabilities Found

| Vulnerability | Severity | CVE ID | Affected Port | Description |
|---------------|----------|--------|----------------|-------------|
| OpenSSH User Enumeration | High | CVE-2018-15473 | 22/tcp | Allows attackers to identify valid users via timing differences. |
| SSL/TLS Weak Cipher Suites | Medium | - | 443/tcp | Use of outdated cryptographic algorithms can lead to data exposure. |

🛡️ Suggested Fixes & Mitigations

### 1. **OpenSSH User Enumeration**
  Problem: Use firewall rules to restrict SSH access; configure SSH to delay response for invalid users.
  Fix: Upgrade to OpenSSH 7.8 or higher.
  Reference: [CVE-2018-15473](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15473)

### 2. **SSL/TLS Weak Cipher Suites**
  Problem: Enforce modern protocols (TLS 1.2/1.3).
  Fix: Disable weak ciphers in the web server configuration (e.g., Apache, Nginx).
  Reference: [OWASP TLS Guidelines](https://owasp.org/www-project-top-ten/)

### 3. DHCP Server Detection
Problem: A system is acting as a DHCP server (giving out IP addresses), which may not be intended.
Fix: If the system is not supposed to do this, disable the DHCP server service.

### 4. ICMP Timestamp Request Response
Problem: The system replies to timestamp requests, which can reveal system uptime or other useful info to attackers.
Fix: Block or disable timestamp responses to prevent information leakage.

Documentation of Most Critical Vulnerabilities
🔒 1. IP Forwarding Enabled
Severity: Medium
Description:
The system is set to forward network traffic, which can allow attackers to intercept or redirect information across the network. This behavior is risky if the system is not intended to act as a router.
Impact:
May enable man-in-the-middle (MITM) attacks or unauthorized data routing.
Recommended Fix:
Turn off IP forwarding on systems that are not used for routing purposes.

🔒 2. SMB Signing Not Required
Severity: Medium
Description:
SMB (Server Message Block) is used for sharing files and printers on a network. If signing is not required, data can be intercepted or changed without detection.
Impact:
Attackers can modify or read the SMB data, which is a risk for data tampering and network spoofing.
Recommended Fix:
Make SMB signing mandatory so all network messages are verified and secure.
