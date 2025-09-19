```
     _____ _   _ _____ _   __ _   __  ___
    |  _  | | | |  _  | | / /| | / / / _ \
    | | | | | | | | | | |/ / | |/ / / /_\ \
    | | | | | | | | | |    \ |    \ |  _  |
    \ \/' / |_| \ \_/ / |\  \| |\  \| | | |
     \_/\_\\___/ \___/\_| \_/\_| \_/\_| |_/
```
# QUOKKA
## QUick Observation Of LAN K(K)nowledge Acquisition
Just download and run! Automatically creates and runs in a venv with the dependencies. Requires sudo to read the interface.

Usage:
```sudo ./quokka.py <interface name>```

eg:
```sudo ./quokka.py eth0```

You can pass in a .json file with VLAN mappings to IDs eg:
```
{
    "10.46.80.0/21": 30,
    "10.46.88.0/21": 40
}
```
and then run:
```sudo ./quokka.py <interface name> --vlan-map vlan_map.json```

## Dependcies
<ol>
     <li><b>Scapy</b> <i>Packet Manipulation Library</i>: https://github.com/secdev/scapy</li>
</ol>
