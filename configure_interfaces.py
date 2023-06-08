import shutil
import netifaces
import getpass

# Target file paths
hostapd_conf_path = '/etc/hostapd/hostapd.conf'
dhcpd_conf_path = '/etc/dhcp/dhcpd.conf'
nftables_conf_path = '/etc/nftables.conf'
interfaces_conf_path = '/etc/network/interfaces.conf'

# Source file paths
hostapd_conf_template_path = 'templates/hostapd.conf.template'
dhcpd_conf_template_path = 'templates/dhcpd.conf.template'
nftables_conf_template_path = 'templates/nftables.conf.template'
interfaces_conf_template_path = 'templates/interfaces.conf.template'

# Backup file paths
hostapd_conf_backup_path = hostapd_conf_path + '.backup'
dhcpd_conf_backup_path = dhcpd_conf_path + '.backup'
nftables_conf_backup_path = nftables_conf_path + '.backup'
interfaces_conf_backup_path = interfaces_conf_path + '.backup'

def get_network_interfaces():
    interfaces = netifaces.interfaces()
    return [iface for iface in interfaces if iface != 'lo']

def select_interface(interfaces, interface_type):
    print(f"Select {interface_type} interface:")
    for i, iface in enumerate(interfaces):
        print(f"{i+1}. {iface}")
    
    while True:
        selection = input("Enter the number of the interface: ")
        try:
            selection = int(selection)
            if 1 <= selection <= len(interfaces):
                return interfaces[selection-1]
            else:
                print("Invalid selection. Try again.")
        except ValueError:
            print("Invalid input. Try again.")

# Get all network interfaces
all_interfaces = get_network_interfaces()

# Prompt user to select the external interface
external_if = select_interface(all_interfaces, "external")

# Remove the selected external interface from the list of interfaces
internal_interfaces = all_interfaces.copy()
internal_interfaces.remove(external_if)

# Prompt user to select the internal interface
internal_if = select_interface(internal_interfaces, "internal")

# Display the selected interfaces
print("Selected interfaces:")
print("External Interface:", external_if)
print("Internal Interface:", internal_if)

# Get backups of files
shutil.copyfile(hostapd_conf_path, hostapd_conf_backup_path)
shutil.copyfile(dhcpd_conf_path, dhcpd_conf_backup_path)
shutil.copyfile(nftables_conf_path, nftables_conf_backup_path)
shutil.copyfile(interfaces_conf_path, interfaces_conf_backup_path)

ap_name = input("Please enter name of access point:")
password = getpass("Please enter password of access point")
with open(hostapd_conf_template_path, 'r') as hostapd_template_file:
    hostapd_template = hostapd_template_file.read()
    hostapd_modified = hostapd_template.replace('INTERFACE_NAME', internal_if)
    hostapd_modified = hostapd_template.replace('AP_NAME', ap_name)
    hostapd_modified = hostapd_template.replace('PASSWORD', password)

    with open(hostapd_conf_path, 'w') as hostapd_file:
        hostapd_file.write(hostapd_modified)

with open(dhcpd_conf_template_path, 'r') as dhcpd_template_file:
    dhcpd_template = dhcpd_template_file.read()

    with open(dhcpd_conf_path, 'w') as dhcpd_file:
        dhcpd_file.write(dhcpd_template)
        
with open(nftables_conf_template_path, 'r') as nftables_template_file:
    nftables_template = nftables_template_file.read()
    nftables_modified = nftables_template.replace('EXTERNAL_IF', external_if)
    nftables_modified = nftables_modified.replace('INTERNAL_IF', internal_if)

    with open(nftables_conf_path, 'w') as nftables_file:
        nftables_file.write(nftables_modified)
        
with open(interfaces_conf_template_path, 'r') as interfaces_template_file:
    interfaces_template = interfaces_template_file.read()
    nftables_modified = nftables_template.replace('EXTERNAL_IF', external_if)
    nftables_modified = nftables_modified.replace('INTERNAL_IF', internal_if)

    with open(nftables_conf_path, 'w') as nftables_file:
        nftables_file.write(nftables_modified)