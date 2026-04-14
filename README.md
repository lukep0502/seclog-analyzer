# 🛡️ SecLog Analyzer — SOC Log Analysis & Threat Detection Simulator

A Python-based **Security Operations Center (SOC) simulation tool** designed to analyze authentication logs, detect security threats, and visualize incidents through a web-based dashboard.

This project replicates core **SIEM-like capabilities**, including **log parsing**, **event correlation**, **threat detection**, and **alert prioritization**.

---

## 🧠 Why This Project Matters

This project was developed to simulate real-world tasks performed in entry-level SOC environments, such as:

- Log monitoring and analysis  
- Incident triage and prioritization  
- Detection of suspicious authentication activity  
- Event correlation across logs  

It demonstrates how raw log data can be transformed into **actionable security insights**, reflecting common workflows used by SOC analysts.

---

## 🛠️ Tech Stack

- Python  
- Flask  
- JSON  
- Chart.js  
- Log Analysis (auth.log)  

---

## 📌 Overview

**SecLog Analyzer** simulates real-world SOC workflows by ingesting authentication logs (`auth.log`) and transforming raw data into structured and actionable security events.

The system identifies suspicious behaviors, correlates events, and generates **prioritized alerts**, mimicking how analysts operate in a SOC environment.

---

## 🚨 **Project Highlights**

- 🔍 **Log Parsing Pipeline**  
  Converts raw authentication logs into structured security events  

- 🧠 **Threat Detection Engine**  
  Identifies multiple attack patterns using rule-based logic  

- 🔗 **Event Correlation**  
  Detects attack sequences (e.g., failed → successful login)  

- 📊 **Interactive Dashboard**  
  Visualizes alerts, severity levels, and incident timelines  

- ⚠️ **Alert Classification**  
  Categorizes incidents into `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`  

- 💾 **SIEM-like Output**  
  Exports structured alerts in JSON format  

---

## 🧪 Sample Data

This repository includes a sample authentication log for testing purposes:

- `logs/example_auth.log`

All data in this file is synthetic and generated for simulation.

Real-world logs are intentionally excluded to follow security and privacy best practices.

## 📦 Output Data

Generated alerts are stored in:

- `output/alerts.json`

This file is dynamically created during execution and is not included in the repository.

The `output/` directory is preserved using a placeholder file.

## 🔍 **Detection Capabilities**

### 🔴 **Brute Force Attack Detection**
Identifies repeated failed login attempts from the same IP address.

### 🔥 **Account Compromise Detection**
Correlates failed login attempts followed by a successful authentication.

### ⚠️ **Suspicious Login Detection**
Detects login attempts from different IP addresses within a short time window.

### 🕒 **Off-Hours Activity Detection**
Flags logins occurring outside standard business hours (**08:00–18:00**).

---

## 🧠 **Architecture Overview**

The project follows a simplified SOC pipeline:

1. **Log Ingestion** → Reads authentication logs  
2. **Parsing Layer** → Extracts structured fields (timestamp, user, IP, event)  
3. **Detection Engine** → Applies security rules and correlations  
4. **Alert Generation** → Assigns severity levels  
5. **Data Output** → Exports alerts (JSON)  
6. **Visualization Layer** → Displays alerts via Flask dashboard  

---

## 📊 **Dashboard Features**

The web dashboard provides a centralized view of security events:

- 📌 **Severity summary cards** (LOW → CRITICAL)  
- 📂 **Alerts grouped by detection type**  
- 📈 **Chart.js visualization of alert distribution**  
- 🕵️ **Incident timeline** (chronological event tracking)  

---

## 🧠 **Skills Demonstrated**

- Security log analysis  
- Threat detection engineering  
- Event correlation logic  
- Behavioral anomaly detection  
- Incident prioritization (SOC workflow)  
- Backend development with Python  
- Web visualization with Flask  
- Data structuring and serialization (JSON)  

---

## 🌐 **SOC / SIEM Relevance**

This project is conceptually aligned with real-world tools such as:

- **Splunk**  
- **Wazuh**  
- **IBM QRadar**  

It demonstrates how security teams:

- Monitor authentication activity  
- Detect suspicious behavior  
- Correlate events across logs  
- Prioritize incidents for investigation  

---

## 🔐 **Security Considerations**

- Runs locally (**127.0.0.1**)  
- No external input processing  
- No exposed services or database  
- Designed for safe, controlled testing  
- Debug mode should be disabled in production  

---

## ⚙️ **How to Run**

### **1. Install dependencies**
```bash
pip install flask
```

### **2. Run the analyzer**
```bash
  python src/analyzer.py
```

### **3. Start the dashboard**
```bash
  python dashboard/app.py
```

### **4. Access the dashboard**
```bash
  http://127.0.0.1:5000
```

## 📸 **Screenshots**

To enhance the visual quality and credibility of this project, Below are examples of the SOC dashboard and detected incidents::

### 📷 SOC Dashboard Overview
<p align="center">
  <img src="images/dashboard-overview.png" width="800"/>
</p>

### 🚨 Incident Analysis View
<p align="center">
  <img src="images/incident-analysis.png" width="800"/>
</p>

## 🚀 **Future Improvements**

- Real-time log ingestion  
- Advanced filtering (**user / IP / time range**)  
- Enhanced visual analytics  
- Detection rule optimization  
- Integration with external SIEM tools  

---

## 👨‍💻 **Author**

**Lucas Pichilingue Rohr**  

Cybersecurity-focused Computer Science student with emphasis on **SOC operations**, **threat detection**, and **log analysis**.

---

## 📜 **License**

This project is intended for **educational and portfolio purposes**.