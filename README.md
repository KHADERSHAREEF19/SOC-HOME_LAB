<img width="1472" height="680" alt="image" src="https://github.com/user-attachments/assets/5c6f5acc-68e4-4069-bdbf-fd55d04e094d" /><h1 align="center">🛡️ Basic SOC Homelab</h1>

<p align="center">
  <b>A Basic, Cost-Free SOC Homelab Project for Detection Engineering & Adversary Simulation</b>
</p>
<p align="center">

</p>

<hr>

<!-- NODE OVERVIEW CARDS -->
<div align="center">
  <table border="0" style="border-collapse: collapse; width: 100%;">
    <tr>
      <!-- KALI CARD -->
      <td width="33%" vertical-align="top" style="padding: 10px;">
        <div style="background-color: #0d1117; border: 2px solid #da3633; border-radius: 8px; padding: 15px; color: #c9d1d9;">
          <h3 style="color: #f85149; margin-top: 0;">⚔️ Kali Linux Machine</h3>
          <p><b>IP Address:</b> <code>192.168.1.8</code></p>
          <p>Adversary simulation device for running attack campaigns and testing detection capabilities.</p>
        </div>
      </td>
      <!-- WINDOWS CARD -->
      <td width="33%" vertical-align="top" style="padding: 10px;">
        <div style="background-color: #0d1117; border: 2px solid #1f6feb; border-radius: 8px; padding: 15px; color: #c9d1d9;">
          <h3 style="color: #58a6ff; margin-top: 0;">💻 Windows 11 Machine</h3>
          <p><b>IP Address:</b> <code>192.168.1.11</code></p>
          <p>Simulates a user device, runs malware detection, and forwards events to the SIEM.</p>
        </div>
      </td>
      <!-- UBUNTU CARD -->
      <td width="33%" vertical-align="top" style="padding: 10px;">
        <div style="background-color: #0d1117; border: 2px solid #238636; border-radius: 8px; padding: 15px; color: #c9d1d9;">
          <h3 style="color: #3fb950; margin-top: 0;">🐧 Ubuntu Server</h3>
          <p><b>IP Address:</b> <code>192.168.1.25</code></p>
          <p>Running Wazuh SIEM/XDR for security operations management, the main machine managing the SOC.</p>
        </div>
      </td>
    </tr>
  </table>
</div>

<hr>

<!-- DOWNLOADS SECTION CARD -->
<div style="background-color: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 20px; color: #c9d1d9;">
  <h2 style="color: #58a6ff; margin-top: 0;">📥 Downloads & Software Links</h2>
  <p>All software used in this project is completely free and open-source:</p>
  <ul>
    <li><b>Hypervisor:</b> <a href="https://www.virtualbox.org/wiki/Downloads" style="color: #58a6ff;">Oracle VirtualBox Download</a></li>
    <li><b>Adversary OS:</b> <a href="https://www.kali.org/get-kali/" style="color: #f85149;">Kali Linux ISO Download</a></li>
    <li><b>Target Endpoint OS:</b> <a href="https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise" style="color: #58a6ff;">Windows 11 Enterprise ISO (Evaluation)</a></li>
    <li><b>SIEM Host OS:</b> <a href="https://ubuntu.com/download/server" style="color: #3fb950;">Ubuntu Server 22.04 LTS ISO</a></li>
    <li><b>SIEM Platform:</b> <a href="https://documentation.wazuh.com/current/quickstart.html" style="color: #3fb950;">Wazuh Documentation & Installer</a></li>
    <li><b>Telemetry Agent:</b> <a href="https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon" style="color: #58a6ff;">Microsoft Sysmon Download</a></li>
  </ul>
</div>

<!-- SETUP PROCEDURE CONTAINER -->
<div style="background-color: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 20px; color: #c9d1d9;">
  <h2 style="color: #58a6ff; margin-top: 0;">🚀 Lab Setup & Installation Guide</h2>

  <!-- PHASE 1 -->
  <div style="border-left: 4px solid #d29922; padding-left: 15px; margin-bottom: 25px;">
    <h3 style="color: #d29922; margin-top: 0;">Phase 1: VirtualBox Network Configuration</h3>
    <ol>
      <li>Open <b>VirtualBox</b> and navigate to <code>File</code> &gt; <code>Tools</code> &gt; <code>Network Manager</code>.</li>
      <li>Create a <b>Host-Only Network</b> or use <b>Bridged Adapter</b> mode on all virtual machines so they can communicate on the <code>192.168.1.0/24</code> subnet.</li>
    </ol>
  </div>

  <!-- PHASE 2 -->
  <div style="border-left: 4px solid #238636; padding-left: 15px; margin-bottom: 25px;">
    <h3 style="color: #3fb950; margin-top: 0;">Phase 2: Ubuntu Server (Wazuh SIEM Manager) Setup</h3>
    <ol>
      <li>Create a VM for <b>Ubuntu Server 22.04 LTS</b> <i>(Assign 4 vCPUs, 8GB RAM, 50GB Disk)</i>.</li>
      <li>Set static IP address to <code>192.168.1.25</code>.</li>
      <li>Update system packages:
        <pre style="background-color: #161b22; border: 1px solid #30363d; padding: 10px; border-radius: 6px; color: #e6edf3;"><code>sudo apt update && sudo apt upgrade -y</code></pre>
      </li>
      <li>Run the official Wazuh all-in-one installation script:
        <pre style="background-color: #161b22; border: 1px solid #30363d; padding: 10px; border-radius: 6px; color: #e6edf3;"><code>curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a</code></pre>
      </li>
      <li>Access the <b>Wazuh Dashboard</b> by navigating to <code>https://192.168.1.25</code> in your host browser.</li>
    </ol>
  </div>

  <!-- PHASE 3 -->
  <div style="border-left: 4px solid #1f6feb; padding-left: 15px; margin-bottom: 25px;">
    <h3 style="color: #58a6ff; margin-top: 0;">Phase 3: Windows 11 Endpoint Setup</h3>
    <ol>
      <li>Create a VM for <b>Windows 11</b> <i>(Assign 2 vCPUs, 4GB RAM, 60GB Disk)</i> and set static IP <code>192.168.1.11</code>.</li>
      <li>Download and install <b>Sysmon</b> with SwiftOnSecurity configuration:
        <pre style="background-color: #161b22; border: 1px solid #30363d; padding: 10px; border-radius: 6px; color: #e6edf3;"><code>Sysmon64.exe -i sysmonconfig-export.xml</code></pre>
      </li>
      <li>Download the <b>Wazuh Agent</b> installer on Windows 11 and enroll it using PowerShell:
        <pre style="background-color: #161b22; border: 1px solid #30363d; padding: 10px; border-radius: 6px; color: #e6edf3;"><code>wazuh-agent-4.7.0.msi /q WAZUH_MANAGER='192.168.1.25' WAZUH_REGISTRATION_SERVER='192.168.1.25'
NET START WazuhSvc</code></pre>
      </li>
    </ol>
  </div>

  <!-- PHASE 4 -->
  <div style="border-left: 4px solid #da3633; padding-left: 15px; margin-bottom: 25px;">
    <h3 style="color: #f85149; margin-top: 0;">Phase 4: Kali Linux (Adversary Machine) Setup</h3>
    <ol>
      <li>Create a VM for <b>Kali Linux</b> <i>(Assign 2 vCPUs, 4GB RAM, 20GB Disk)</i> and set static IP <code>192.168.1.8</code>.</li>
      <li>Verify connectivity to the Windows target:
        <pre style="background-color: #161b22; border: 1px solid #30363d; padding: 10px; border-radius: 6px; color: #e6edf3;"><code>ping 192.168.1.11</code></pre>
      </li>
      <li>Run attack simulations (e.g., Nmap port scanning or Hydra brute force) to generate log events:
        <pre style="background-color: #161b22; border: 1px solid #30363d; padding: 10px; border-radius: 6px; color: #e6edf3;"><code>nmap -sV -A 192.168.1.11</code></pre>
      </li>
    </ol>
  </div>

  <hr style="border-color: #30363d;">

  <!-- VERIFICATION SECTION -->
  <h2 style="color: #3fb950;">🧪 Verification & SOC Operations</h2>
  <ul>
    <li>Log into the <b>Wazuh Dashboard</b> at <code>https://192.168.1.25</code>.</li>
    <li>Confirm <code>192.168.1.11</code> shows as <b>Active</b> under the <b>Agents</b> tab.</li>
    <li>Perform test attacks from Kali (<code>192.168.1.8</code>) and verify security alerts trigger on the dashboard in real-time.</li>
  </ul>
</div>
<div style="background-color: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 20px; color: #c9d1d9;">
  <h2 style="color: #58a6ff; margin-top: 0;">🔄 LAB Workflow & Telemetry Pipeline</h2>
  
  <pre style="background-color: #161b22; border: 1px solid #30363d; padding: 15px; border-radius: 6px; color: #e6edf3; font-family: monospace;">[ Kali Linux (192.168.1.8) ]
          │
          │ 1. Attacks / Scans (Nmap, Hydra, PowerShell)
          ▼
[ Windows 11 Target (192.168.1.11) ]
          │
          │ 2. Telemetry Generation (Sysmon + Event Viewer)
          ▼
[ Wazuh Agent (192.168.1.11) ]
          │
          │ 3. Encrypted Log Shipping (Port 1514)
          ▼
[ Ubuntu Server / Wazuh Manager (192.168.1.25) ]
          │
          │ 4. Correlation & Alert Generation
          ▼
[ Wazuh Dashboard (SOC Analyst View) ]</pre>

  <h3 style="color: #58a6ff;">📋 Operational Steps</h3>
  <ol>
    <li><b>Attack Emulation:</b> Kali Linux executes simulated scans and exploit attempts against the Windows endpoint.</li>
    <li><b>Telemetry Capture:</b> Windows 11 captures process creation and system events using Sysmon and Event Logs.</li>
    <li><b>Log Shipping:</b> The Wazuh Agent forwards telemetry securely to Ubuntu Server over port 1514.</li>
    <li><b>Correlation & Detection:</b> Wazuh Manager parses logs against detection rules and generates alerts on the SOC dashboard.</li>
  </ol>
</div>
