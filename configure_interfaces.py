import shutil
import netifaces
import getpass

# Target file paths
hostapd_conf_path = '/etc/hostapd/hostapd.conf'
dhcpd_conf_path = '/etc/dhcp/dhcpd.conf'
nftables_conf_path = '/etc/nftables.conf'
interfaces_path = '/etc/network/interfaces'

# Source file paths
hostapd_conf_template_path = 'templates/hostapd.conf.template'
dhcpd_conf_template_path = 'templates/dhcpd.conf.template'
nftables_conf_template_path = 'templates/nftables.conf.template'
interfaces_template_path = 'templates/interfaces.template'
pc_nftables_conf_template_path = 'templates/pc_nftables.conf.template'

# Backup file paths
hostapd_conf_backup_path = hostapd_conf_path + '.backup'
dhcpd_conf_backup_path = dhcpd_conf_path + '.backup'
nftables_conf_backup_path = nftables_conf_path + '.backup'
interfaces_backup_path = interfaces_path + '.backup'

def backup_file(source_path, backup_path):
    try:
        shutil.copyfile(source_path, backup_path)
        print(f"{source_path} yedeği oluşturuldu.")
    except FileNotFoundError as e:
        print(f"Hata: {source_path} dosyası bulunamadı: {e}")

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

def setup_router():

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

    # Backup files
    backup_file(hostapd_conf_path, hostapd_conf_backup_path)
    backup_file(dhcpd_conf_path, dhcpd_conf_backup_path)
    backup_file(nftables_conf_path, nftables_conf_backup_path)
    backup_file(interfaces_path, interfaces_backup_path)

    ap_name = input("Please enter name of access point: ")
    password = getpass.getpass("Please enter password of access point: ")

    with open(hostapd_conf_template_path, 'r') as hostapd_template_file:
        hostapd_template = hostapd_template_file.read()
        hostapd_modified = hostapd_template.replace('INTERFACE_NAME', internal_if)
        hostapd_modified = hostapd_modified.replace('AP_NAME', ap_name)
        hostapd_modified = hostapd_modified.replace('PASSWORD', password)

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

    with open(interfaces_template_path, 'r') as interfaces_template_file:
        interfaces_template = interfaces_template_file.read()
        interfaces_modified = interfaces_template.replace('EXTERNAL_IF', external_if)
        interfaces_modified = interfaces_modified.replace('INTERNAL_IF', internal_if)

        with open(interfaces_path, 'w') as interfaces_file:
            interfaces_file.write(interfaces_modified)

def setup_pc():
    
    # Backup files
    backup_file(nftables_conf_path, nftables_conf_backup_path)
    
    with open(pc_nftables_conf_template_path, 'r') as nftables_template_file:
        nftables_template = nftables_template_file.read()

        with open(nftables_conf_path, 'w') as nftables_file:
            nftables_file.write(nftables_template)


# Main menu
def main():
    print("1. Setup for Router")
    print("2. Setup for PC")
    while True:
        selection = input("Enter the number of the setup type: ")
        if selection == '1':
            setup_router()
            break
        elif selection == '2':
            setup_pc()
            break
        else:
            print("Invalid selection. Try again.")

if __name__ == "__main__":
    main()
