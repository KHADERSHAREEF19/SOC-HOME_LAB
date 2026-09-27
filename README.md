
html
<h1 align="center">🛡️ Basic SOC Homelab</h1>

<p align="center">
  <b>A Basic, Cost-Free SOC Homelab Project for Detection Engineering & Adversary Simulation</b>[cite: 1]
</p>

<hr>

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
