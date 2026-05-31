# BTA SOC Simulation Platform

> A Security Operations Center (SOC) simulation environment for transportation infrastructure featuring threat generation, security monitoring, incident investigation, and Graylog-based detection workflows.

---

## Overview

The **BTA SOC Simulation Platform** is a cybersecurity simulation environment built around a fictional metropolitan transit authority responsible for public transportation services, fleet operations, passenger ticketing, and payment processing.

The project combines SOC concepts, threat modeling, detection engineering, incident response, and SIEM monitoring into a unified platform that allows security scenarios to be generated from realistic business workflows and investigated through centralized log analysis.

Rather than analyzing static datasets, the platform produces security telemetry from simulated operational systems and forwards events into Graylog for monitoring and investigation.

The project was developed as part of coursework focused on:

- Security Operations Centers (SOC)
- Digital Forensics and Incident Response (DFIR)
- Threat Intelligence
- Detection Engineering
- Incident Response
- SIEM Architecture
- Threat Hunting

---

## Scenario

The simulated organization, **Bangalore Transit Authority (BTA)**, operates:

- 500 public transit buses
- 20 metro rail trains
- Contactless payment terminals
- GPS-based fleet tracking
- Passenger ticketing systems
- Fleet management services
- Administrative monitoring infrastructure

The organization relies heavily on both IT and operational technology systems to maintain transportation services, collect fares, and ensure passenger safety.

The platform models threats against these systems and demonstrates how a modern SOC can identify, investigate, contain, and recover from security incidents.

---

## Features

### Fleet Management Simulation

- Fleet monitoring workflows
- Route and vehicle tracking
- GPS-based location services
- Vehicle lookup and search functionality
- GPS spoofing attack simulation
- Ghost bus scenario generation

### Passenger Ticketing Platform

- Ticket booking workflows
- Payment processing simulation
- Transaction generation
- Passenger activity tracking
- Payment terminal telemetry

### Administrative Console

- Ticket investigation interface
- Operational dashboards
- Authentication monitoring exercises
- Security scenario management
- Threat simulation controls

### Threat Simulations

The platform supports multiple security scenarios designed to emulate realistic attack patterns:

#### DNS Tunneling

Simulates covert data exfiltration using DNS requests originating from payment infrastructure.

#### GPS Spoofing

Generates manipulated vehicle location data resulting in fleet tracking inconsistencies and ghost vehicle behavior.

#### Payment Terminal Skimming

Models compromised payment terminals generating suspicious transaction activity and exfiltration events.

#### Authentication Abuse

Produces login sequences suitable for brute-force detection and credential abuse investigations.

#### Ransomware Indicators

Generates security events associated with persistence mechanisms, suspicious service creation, and malicious execution patterns.

---

## Security Monitoring

The platform integrates with Graylog to provide centralized monitoring and investigation capabilities.

Generated events include:

- Authentication activity
- Ticketing operations
- Fleet queries
- Payment transactions
- DNS requests
- GPS telemetry
- Administrative actions
- Security scenario indicators

Analysts can investigate:

- Authentication anomalies
- DNS tunneling attempts
- GPS integrity violations
- Payment terminal compromise
- Suspicious service installations
- Potential ransomware behavior

---

## Screenshots

### Fleet Management Admin Console

Administrative dashboard used to manage threat simulations and security scenarios.

<img width="1280" height="829" alt="img1" src="https://github.com/user-attachments/assets/ea9e81d9-fc51-4ee2-9afe-bb2b1e997c09" />


---

### Ticket Investigation Console

Investigation interface allowing analysts to search ticket activity and generate operational telemetry.

<img width="1600" height="1036" alt="img3" src="https://github.com/user-attachments/assets/4202787e-18ae-49c4-948e-0d1404510915" />


---

### Passenger Ticket Booking

Customer-facing booking workflow that generates transaction and payment telemetry.

<img width="1600" height="1036" alt="img5" src="https://github.com/user-attachments/assets/41067337-c5e4-474c-b7ac-6c4eb452bd6c" />


---

### Fleet Monitoring Interface

Fleet lookup and vehicle monitoring system supporting GPS spoofing simulations.



---

### Graylog Investigation Dashboard

Centralized log monitoring environment used to investigate generated events and security alerts.

<img width="1592" height="765" alt="img6" src="https://github.com/user-attachments/assets/99db1a4b-c01c-408d-ba28-b67a13cce6ec" />


---

## Architecture

### Frontend

- React
- JavaScript
- REST API Integration

### Backend

- FastAPI
- Python

### Monitoring Stack

- Graylog
- Structured JSON Logging

### Security Components

- Threat Simulation Engine
- Event Generation Pipeline
- Detection Workflows
- Investigation Console
- SOC Scenario Framework

---

## Example Security Events

The platform generates realistic security telemetry including:

### DNS Tunneling

```json
{
  "event_source": "Firewall NetFlow",
  "destination_port": 53,
  "destination_domain": "attacker-c2-server.com",
  "payload_length": 145
}
```

### Suspicious Service Installation

```json
{
  "event_id": 7045,
  "service_name": "SysUpdater",
  "status": "New Service Installed"
}
```

### GPS Anomaly

```json
{
  "event_type": "gps_signal_anomaly",
  "vehicle_status": "spoofed"
}
```

### Payment Terminal Tampering

```json
{
  "event_type": "payment_skimming",
  "terminal_id": "A01-PAY-014"
}
```

---

## SOC Concepts Demonstrated

### Threat Modeling

- Asset identification
- CIA classification
- Threat actor analysis
- Risk assessment

### Detection Engineering

- Correlation rule design
- Event enrichment
- Alert generation
- Indicator analysis

### Threat Intelligence

- IOC workflows
- MITRE ATT&CK mapping
- Threat enrichment concepts
- Adversary behavior analysis

### Incident Response

- Detection
- Validation
- Containment
- Eradication
- Recovery
- Lessons Learned

### Threat Hunting

- Authentication anomalies
- DNS tunneling investigations
- GPS integrity validation
- Payment infrastructure monitoring

---

## Learning Outcomes

This project demonstrates practical understanding of:

- Security Operations Centers (SOC)
- SIEM Architecture
- Graylog Monitoring
- Threat Detection
- Threat Hunting
- Incident Response
- Threat Intelligence
- Detection Engineering
- MITRE ATT&CK Framework
- Transportation Infrastructure Security

---

## Future Improvements

Potential extensions include:

- Wazuh integration
- Automated alert correlation
- SOAR playbooks
- Real-time streaming telemetry
- Additional MITRE ATT&CK coverage
- Dashboard analytics
- Detection rule testing framework
- Multi-tenant SOC scenarios

---

## Team

**Aniket Sompura** PES1UG23CS074

**Sumedh Suresh** PES1UG23CS610

---

## Disclaimer

This project was developed for educational purposes and is intended to demonstrate SOC workflows, threat detection methodologies, incident response processes, and cybersecurity monitoring concepts within a simulated transportation infrastructure environment.
