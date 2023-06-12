# firewall_project

This project is a machine learning based firewall. Developed in Debian-bullseye. This program may not be compatible with other operating systems.

This program simply captures network packets and performs stream-based analysis on them. The data obtained from this process is written to a .csv file. A concurrent Python program uses a pre-trained random forest model to classify the data and identify potentially malicious IP addresses. Subsequently, it executes the corresponding command with nftables to block these IP addresses. Incoming packets from these IP addresses are dropped before reaching the user.
