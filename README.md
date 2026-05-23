# Network Scanner

![C++](https://img.shields.io/badge/C++-17-blue)
![Qt6](https://img.shields.io/badge/Qt-6.0+-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20|%20Linux%20|%20macOS-lightgrey)

Network-Scanner is a highly tactical, cross-platform Network Scanner re-engineered from the ground up in C++ and Qt6.

## Features

1. **Full C++ / Qt Transition**: Rewritten natively for maximum multi-threading performance and memory safety.
2. **True Cross-Platform Design**: Runs natively on Windows, macOS, and Linux without Python dependency hell.
3. **Immersive Hacker Theme**: Custom UI/UX featuring deep black backgrounds with neon green vector typography and borders.
4. **Intelligent IP Range Parsing**: Support for sequential definitions (e.g. `192.168.1.1-254`).
5. **Real-time Console Activity Log**: Built-in CLI-style output capturing deep scan analytics instantly.
6. **Live Multi-column Filtering**: Asynchronous real-time search filtering by IP, Name, MAC, or Vendor.
7. **Thread Management**: Direct control over scanning thread counts via UI.
8. **Adjustable Ping Timeouts**: Millisecond-level accuracy control for target discovery constraints.
9. **MAC Vendor Fingerprinting**: Automated resolution of MAC addresses to device hardware vendors.
10. **JSON Data Export**: Full tactical data serialization into standard JSON format.
11. **HTML Interactive Report Export**: Generate beautiful tabular HTML web files for network auditing.
12. **CSV Database Export**: Native spreadsheet ingestion.
13. **Continuous Monitor Mode**: Loop sweeps infinitely to monitor devices dropping or joining the net.
14. **Custom Target Tagging**: Allow analysts to right-click and assign custom alias tags to network nodes.
15. **Wake-on-LAN (WoL) Hooks**: Framework to cast magic packets to sleeping interfaces.
16. **TCP Port Scan Integration**: Context-menu bindings ready for comprehensive service enumeration.
17. **ICMP Traceroute Hooks**: Route mapping shortcuts built directly into the context dashboard.
18. **Subnet Calculator Stub**: Mathematical dashboard for dividing CIDR blocks and mapping broadcast logic.
19. **Scan Profile Persistence**: Save and reload custom timeout/thread/IP range configurations.
20. **One-Click Browser Injection**: Open HTTP targets instantly via desktop service routing.

## Build Instructions (CMake)

You will need a C++17 compliant compiler and Qt6 installed on your system.

```bash
mkdir build
cd build
cmake ..
make
