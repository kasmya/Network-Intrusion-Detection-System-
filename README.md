# Network Intrusion Detection System (NIDS)

A Python-based Network Intrusion Detection System that leverages open-source tools like Scapy, PyShark, and YARA to monitor network traffic and identify potential malicious activity in real-time.

## 📖 Overview

This project implements a lightweight yet powerful NIDS capable of analyzing live network packets, applying detection rules, and alerting administrators to suspicious behavior. The system is designed for cybersecurity education, research, and practical network monitoring applications.

## ✨ Features

- **Real-time Packet Capture**: Sniffs and analyzes live network traffic from specified interfaces
- **Multi-Tool Analysis**: Utilizes Scapy for packet manipulation and PyShark for deep packet inspection
- **YARA Rule Integration**: Applies customizable YARA rules to detect known attack patterns and signatures
- **Protocol Analysis**: Inspects various network protocols (TCP, UDP, HTTP, DNS, etc.) for anomalies
- **Alert System**: Generates real-time alerts for detected intrusions with detailed context
- **Logging & Reporting**: Maintains comprehensive logs of all detected events for forensic analysis
- **Modular Architecture**: Easily extensible with new detection modules and rule sets

## 🛠️ Technology Stack

- **Python 3.x** - Core programming language
- **Scapy** - Packet manipulation and network discovery
- **PyShark** - Wireshark/TShark integration for packet analysis
- **YARA** - Pattern matching for malware identification
- **argparse** - Command-line interface
- **logging** - System logging and alert management

## 📁 Project Structure

```
Network-Intrusion-Detection-System-/
├── nids_final.py              # Main NIDS implementation
├── nids_implementation.py     # Alternative/experimental implementation
├── rules.txt                  # YARA/signature rules for detection
├── Final Project Report.pdf   # Comprehensive project documentation
├── Final PPT_.pdf            # Final presentation slides
├── Synopsis.pdf              # Project synopsis and proposal
└── Synopsis PPT.pdf          # Synopsis presentation slides
```

## 🚀 Installation & Setup

### Prerequisites

- Python 3.7 or higher
- Network interface with promiscuous mode capability (for packet capture)
- Administrative/root privileges (for raw socket operations)

### Step 1: Clone the Repository

```bash
git clone https://github.com/kasmya/Network-Intrusion-Detection-System-.git
cd Network-Intrusion-Detection-System-
```

### Step 2: Install Dependencies

```bash
pip install scapy pyshark yara-python
```

*Note: You may also need to install TShark/Wireshark for PyShark to function properly.*

### Step 3: Configure Rules

Edit `rules.txt` to customize detection patterns or add your own YARA rules for specific threats.

### Step 4: Run the NIDS

```bash
# Basic usage
python nids_final.py -i eth0

# With custom rule file
python nids_final.py -i eth0 -r rules.txt

# Verbose mode for detailed output
python nids_final.py -i eth0 -v

# Save alerts to log file
python nids_final.py -i eth0 -l alerts.log
```

## 📝 Usage Examples

### Monitor Default Interface

```bash
python nids_final.py
```

### Monitor Specific Interface with Custom Rules

```bash
python nids_final.py -i wlan0 -r my_custom_rules.txt
```

### Run in Background with Logging

```bash
python nids_final.py -i eth0 -l /var/log/nids_alerts.log &
```

## 🔍 Detection Capabilities

The system can identify various types of network intrusions including:

- **Port Scans**: Detection of horizontal and vertical port scanning attempts
- **DoS/DDoS Attacks**: Identification of flooding and resource exhaustion attacks
- **Malware Traffic**: Recognition of known malicious payloads and C2 communications
- **Protocol Anomalies**: Detection of protocol violations and unusual packet structures
- **Suspicious Payloads**: Pattern matching for exploit code and shell commands
- **Data Exfiltration**: Identification of unauthorized data transfer patterns

## ⚙️ Configuration

### Rule File Format

The `rules.txt` file uses a simple format for defining detection patterns:

```
# Comment lines start with #
# Basic signature example
alert tcp any any -> any 80 (content:"GET /evil.php"; msg:"Malicious PHP request";)

# YARA rule integration
rule MaliciousPDF
{
    strings:
        $ = "/JavaScript"
        $ = "/OpenAction"
    condition:
        any of them
}
```

### Command-line Arguments

- `-i`, `--interface`: Network interface to monitor (default: first available)
- `-r`, `--rules`: Path to rule file (default: rules.txt)
- `-l`, `--logfile`: Path to alert log file
- `-v`, `--verbose`: Enable verbose output
- `-q`, `--quiet`: Suppress non-alert output
- `-h`, `--help`: Show help message

## 📊 Output & Alerts

When the NIDS detects suspicious activity, it generates alerts in the following format:

```
[ALERT] [2025-04-24 15:30:22] Potential port scan detected from 192.168.1.100
    Source: 192.168.1.100:54321
    Destination: 192.168.1.50:1-1024
    Protocol: TCP
    Rule: port_scan_sig_001
```

Alerts include:
- Timestamp of detection
- Source and destination IP addresses and ports
- Protocol information
- Triggering rule identifier
- Severity level (INFO, WARNING, ALERT, CRITICAL)

## 📄 Documentation

The repository includes comprehensive documentation:

1. **Final Project Report.pdf**: Complete technical documentation covering implementation details, algorithms, testing methodology, and results
2. **Final PPT_.pdf**: Presentation slides summarizing the project
3. **Synopsis.pdf**: Initial project proposal and scope definition
4. **Synopsis PPT.pdf**: Synopsis presentation slides

## 🤝 Contributing

Contributions to improve the NIDS are welcome! Here's how you can help:

1. **Report Bugs**: Open an issue with detailed steps to reproduce the problem
2. **Suggest Features**: Propose new detection capabilities or improvements
3. **Submit Pull Requests**: 
   - Add new detection rules to `rules.txt`
   - Improve packet parsing algorithms
   - Enhance performance or add new protocol support
   - Fix bugs or improve documentation

### Development Guidelines

- Follow PEP 8 style guidelines for Python code
- Add comments for complex algorithms and functions
- Update documentation when adding new features
- Test changes thoroughly before submitting

## ⚠️ Limitations & Considerations

- **Performance Impact**: Packet inspection may affect network performance on high-traffic networks
- **False Positives**: Rule-based systems may generate false alerts; tune rules for your environment
- **Encrypted Traffic**: The system cannot inspect encrypted payloads (HTTPS, SSH, etc.)
- **Legal Compliance**: Ensure you have proper authorization to monitor target networks
- **Evasion Techniques**: Sophisticated attacks may use evasion techniques to bypass detection

## 🔒 Legal & Ethical Use

**Important**: This tool should only be used on:
- Networks you own or administer
- Networks where you have explicit written permission to perform monitoring
- Educational or research environments with proper isolation

Unauthorized network monitoring may violate laws and regulations. Always ensure compliance with local, state, and federal laws regarding network surveillance and privacy.

## 📚 Learning Resources

- **Scapy Documentation**: https://scapy.readthedocs.io/
- **PyShark Documentation**: https://github.com/KimiNewt/pyshark
- **YARA Official Documentation**: https://yara.readthedocs.io/
- **Network Security Monitoring**: Richard Bejtlich's "The Practice of Network Security Monitoring"
- **Intrusion Detection**: Stephen Northcutt's "Network Intrusion Detection: An Analyst's Handbook"

## 👥 Acknowledgments

- The developers of Scapy, PyShark, and YARA for creating excellent open-source tools
- The cybersecurity research community for sharing knowledge and techniques
- All contributors and testers who helped improve this project

## 📄 License

This project is available for educational and research purposes. For specific licensing information, please contact the repository owner.

---

## 📞 Support

For questions, issues, or suggestions:
1. Check the project documentation in the PDF files
2. Review existing issues on GitHub
3. Submit a new issue with detailed information about your question or problem

---

*Last Updated: April 2025*  
*Maintainer: kasmya*  
*Project Status: Active Development*
