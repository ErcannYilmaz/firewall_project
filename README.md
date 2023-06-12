# firewall_project

This project is a machine learning based firewall. Developed in Debian-bullseye. This program may not be compatible with other operating systems.

This program simply captures network packets and performs stream-based analysis on them. The data obtained from this process is written to a .csv file. A concurrent Python program uses a pre-trained random forest model to classify the data and identify potentially malicious IP addresses. Subsequently, it executes the corresponding command with nftables to block these IP addresses. Incoming packets from these IP addresses are dropped before reaching the user.

The program is in its early stages, and errors may be encountered in some cases. The planned areas for development are as follows:

   1-) The completion process of network flow should be detected more accurately and precisely.
   2-) The code needs to be modularized. Its current state makes development challenging. The code will be transformed into a modular structure.
   3-) A web interface should be designed to provide control over blocked IP addresses and the ability to track certain data.
