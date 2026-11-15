# Zero-Trust Network Security Architecture with Role-Based Access Control

## Project Overview

This project implements a Zero-Trust Network Security Architecture with Role-Based Access Control (RBAC) for a web application.

The main objective is to improve network security through network segmentation, access restrictions, device authentication and centralized monitoring.

## Technologies Used

- Cisco Packet Tracer
- Cisco 1941 Router
- Cisco 2960 Switch
- Python Flask
- HTML and CSS
- SQLite

## Features

1. VLAN-based Network Segmentation
2. Router-on-a-Stick Inter-VLAN Routing
3. Extended Access Control Lists (ACL)
4. Sticky MAC Address Port Security
5. Centralized Syslog Monitoring
6. NTP Time Synchronization
7. DMZ Web Server Isolation
8. Role-Based Access Control (RBAC)
9. Flask-based Authentication and Authorization

## VLAN Configuration

| VLAN | Department | Network |
|---|---|---|
| 10 | Admin | 192.168.10.0/24 |
| 20 | Employee | 192.168.20.0/24 |
| 30 | Student | 192.168.30.0/24 |
| 40 | Server | 192.168.40.0/24 |
| 50 | Guest | 192.168.50.0/24 |
| 60 | IT | 192.168.60.0/24 |
| 61 | HR | 192.168.61.0/24 |
| 62 | Finance | 192.168.62.0/24 |
| 63 | Sales | 192.168.63.0/24 |
| 64 | Marketing | 192.168.64.0/24 |
| 65 | Operations | 192.168.65.0/24 |
| 70 | DMZ | 192.168.70.0/24 |

## DMZ Configuration

- DMZ Gateway: 192.168.70.1
- DMZ Web Server: 192.168.70.10
- VLAN: 70

An extended ACL restricts traffic initiated from the DMZ toward protected internal networks.

## Testing

- Verified VLAN connectivity and segmentation.
- Tested ACL-based access restrictions.
- Tested sticky MAC port security and unauthorized MAC violations.
- Verified centralized Syslog messages.
- Verified Router0 NTP synchronization.
- Tested HTTP access to the DMZ Web Server.
- Verified DMZ-to-internal network restrictions.

## Project Structure

- Packet-Tracer: Network simulation file.
- Flask-Application: Web application source code.
- Screenshots: Project implementation screenshots.
- Documentation: Project presentation and supporting documents.

## Important Note

The Flask application and Cisco Packet Tracer network are separate demonstrations and are not live-integrated.

## Conclusion

This project demonstrates how Zero-Trust principles, VLAN segmentation, ACLs, port security, monitoring and role-based authorization can improve network security.

