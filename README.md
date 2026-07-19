# Java Deep Packet Inspection (DPI) Engine

A Java-based **Deep Packet Inspection (DPI)** application that captures live network traffic, analyzes packets across multiple protocol layers, detects suspicious activities, manages network flows, and generates professional **CSV**, **HTML Dashboard**, and **PDF** reports.

---

## Features

- 📡 Live packet capture using Pcap4J
- 🌐 Ethernet, IPv4, TCP and UDP packet parsing
- 🌍 HTTP request and response parsing
- 🚦 TCP Flag analysis
- 🔄 Network Flow Management
- 🚨 Port Scan Detection
- 🖥️ Top Talker Identification
- 📊 Traffic Statistics
- 📄 CSV Report Generation
- 📈 Interactive HTML Dashboard
- 📑 Professional PDF Report Generation

---

## Project Overview

Deep Packet Inspection (DPI) is a network traffic analysis technique that inspects both packet headers and payloads to identify protocols, monitor traffic, detect suspicious activities, and generate detailed traffic reports.

This project is developed in **Java** using the **Pcap4J** library. It captures live network packets, analyzes multiple protocol layers, tracks active network flows, detects potential port scan attacks, identifies top network talkers, and generates comprehensive reports in **CSV**, **HTML**, and **PDF** formats.

The primary objective of this project is to demonstrate practical knowledge of **Computer Networks**, **Packet Analysis**, and **Network Security** concepts.

The project follows a modular architecture with separate components for packet capture, protocol parsing, traffic classification, security analysis, statistics collection, flow management, and report generation, making it easy to extend with additional protocols and detection modules.

---

## Tech Stack

- **Language:** Java
- **Build Tool:** Maven
- **Packet Capture Library:** Pcap4J
- **PDF Generation:** OpenPDF
- **Frontend Dashboard:** HTML, CSS, JavaScript
- **Charts:** Chart.js
- **IDE:** Visual Studio Code

---

## Supported Protocols

- Ethernet
- IPv4
- TCP
- UDP
- HTTP
- DNS

---

## Security Detection

The DPI engine detects:

- SYN Scan
- FIN Scan
- NULL Scan
- XMAS Scan
- Generic Port Scan

---

## Project Architecture

```text
                 Live Network Traffic
                         │
                         ▼
                 Packet Capture (Pcap4J)
                         │
                         ▼
                  Packet Parsing
      ┌──────────┬──────────┬──────────┐
      │          │          │          │
  Ethernet     IPv4      TCP/UDP      HTTP
                         │
                         ▼
                 Traffic Classification
                         │
                         ▼
                 Flow Management
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
   Statistics      Security Module    Top Talkers
                   (Port Scan)
                         │
                         ▼
                  Report Generation
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
      CSV        HTML Dashboard        PDF
```

---

## Project Structure

```text
java-deep-packet-inspection-engine/
│
├── src/
│   ├── main/
│   │   └── java/
│   │       └── com/
│   │           └── radhika/
│   │               └── dpi/
│   │                   ├── capture/
│   │                   │   ├── InterfaceScanner.java
│   │                   │   └── PacketCapture.java
│   │                   │
│   │                   ├── classifier/
│   │                   │   └── TrafficClassifier.java
│   │                   │
│   │                   ├── flow/
│   │                   │   ├── Flow.java
│   │                   │   └── FlowManager.java
│   │                   │
│   │                   ├── model/
│   │                   │   └── PacketInfo.java
│   │                   │
│   │                   ├── parser/
│   │                   │   ├── EthernetParser.java
│   │                   │   ├── IPv4Parser.java
│   │                   │   ├── TCPParser.java
│   │                   │   ├── UDPParser.java
│   │                   │   ├── TCPFlagParser.java
│   │                   │   ├── HTTPParser.java
│   │                   │   └── DNSParser.java
│   │                   │
│   │                   ├── report/
│   │                   │   ├── ReportGenerator.java
│   │                   │   └── PDFReportGenerator.java
│   │                   │
│   │                   ├── security/
│   │                   │   ├── PortScanDetector.java
│   │                   │   └── PortScanInfo.java
│   │                   │
│   │                   ├── statistics/
│   │                   │   ├── Statistics.java
│   │                   │   ├── HostStatistics.java
│   │                   │   └── HostStatisticsManager.java
│   │                   │
│   │                   └── Main.java
│
├── pom.xml
├── README.md
└── .gitignore
```

---

## Reports Generated

The application automatically generates:

- 📄 CSV Report
- 📊 Interactive HTML Dashboard
- 📑 PDF Report

Each report contains:

- Flow Summary
- Traffic Statistics
- Protocol Distribution
- HTTP Requests
- Port Scan Alerts
- Suspicious Hosts
- Top Talker
- Active Flow Details

---

## How to Run

### Prerequisites

- Java JDK 17 or later
- Maven
- Npcap (Windows) or libpcap (Linux)
- Visual Studio Code (or any Java IDE)

### Clone Repository

```bash
git clone https://github.com/Nerkar-Radhika/Java-Deep-Packet-Inspection-Project.git
```

### Navigate to Project

```bash
cd java-deep-packet-inspection-engine
```

### Install Dependencies

```bash
mvn clean install
```

### Run the Project

```bash
mvn exec:java "-Dexec.mainClass=com.radhika.dpi.Main"
```

Select the desired network interface to begin live packet capture.

---

## Screenshots

### Console Output

Displays:

- Live Packet Capture
- Packet Parsing
- HTTP Requests
- TCP Flags
- Flow Statistics

---

### HTML Dashboard

Displays:

- Threat Dashboard
- Active Flows
- Interactive Charts
- Searchable Flow Table

---

### PDF Report

Contains:

- Report Summary
- Threat Summary
- Flow Details
- Report Generation Timestamp

---

## Future Enhancements

- IPv6 Deep Packet Inspection
- Machine Learning based anomaly detection
- Intrusion Detection System (IDS)
- Geo-location based IP Analysis
- Email Alert Notifications
- Real-time Traffic Visualization
- JSON Report Export

---

## License

This project is developed for educational and learning purposes.

