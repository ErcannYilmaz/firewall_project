from colorama import Fore, Style
import joblib
import pandas as pd
import numpy as np
import os
import time
import subprocess

FOLDER_PATH = "/etc/firewall/csv-files"
IP_Addresses = []

file_list = os.listdir(FOLDER_PATH)
for idx in range(len(file_list)):
    file_list[idx] = "/".join([FOLDER_PATH, file_list[idx]])

# Load ML model to make predictions
model = joblib.load('/etc/firewall/random_forest.joblib')

# Get new data to make predictions
def get_data_from_file(filepath):
    return pd.read_csv(filepath)


# Make preprocess on new data to better performance
def preprocess(dataframe):
    # Dealing with NaN values
    dataframe.fillna(0, inplace=True)
    dataframe.src_port = dataframe.src_port.fillna(-1).astype('int64')
    dataframe.dest_port = dataframe.dest_port.fillna(-1).astype('int64')
    IP_Adresses = []

    for index, row in dataframe.iterrows():
        src_ip = row['src_ip']
        dest_ip = row['dest_ip']

        if src_ip and '192.168' in src_ip and src_ip != '192.168.1.1':
            IP_Adresses.append(dest_ip)
        elif dest_ip and '192.168' in dest_ip and dest_ip != '192.168.1.1':
            IP_Adresses.append(src_ip)
        else:
            IP_Adresses.append('Invalid')
        
        for index, item in enumerate(IP_Adresses):
            if item == '192.168.1.1':
                IP_Adresses[index] = "Invalid"
                
    # dropping src_ip ve dest_ip
    dataframe.drop(['src_ip', 'dest_ip'], axis=1, inplace=True)
                
    
    return IP_Adresses, dataframe


# Return True if given file is empty  
def is_file_empty(filepath):
    try:
        if os.path.getsize(filepath) > 147:
            return False
        else:
            return True
    except Exception as e:
        print("Error: couldn't get file size", e)
        return False


# Make predictions with loaded ML model and data
def prediction(loaded_model, data):
    return loaded_model.predict(data)


def block_ip_address(ip_address):
    # Execute the nftables command to block the IP address
    command = ["nft", "add", "element", "ip", "global", "blackhole", "{", ip_address, "}"]
    subprocess.run(command, check=True)
    print(Fore.RED + "IP address blocked:", ip_address + Style.RESET_ALL)
    #command = ["nft", "-f", "/etc/nftables.conf"]
    #subprocess.run(command, check=True)


def empty_file(filepath):
    with open(filepath, 'r') as file:
        first_line = file.readline()  # get first line

    with open(filepath, 'w') as file:
        file.write(first_line)  # write first line to file other lines would be deleted



# Main function
def main():

    while (True):

        for item in file_list:

            if(not is_file_empty(item)):
                data = get_data_from_file(item)
                IP_Addresses, data = preprocess(data)

                for index, row in data.iterrows():
                    data_sample = row.values.reshape(1, -1)
                    result = prediction(model, data_sample)

                    if result == "malicious" and IP_Addresses[index] != "Invalid":
                        with open("malicious_ips.txt", "a") as malicious_file:
                            malicious_file.write(IP_Addresses[index] + "\n")
                            
                        block_ip_address(IP_Addresses[index])

                    elif result == "outlier" and IP_Addresses[index] != "Invalid":
                        with open("outlier_ips.txt", "a") as outlier_file:
                            outlier_file.write(IP_Addresses[index] + "\n")

                empty_file(item)

                time.sleep(10)
                print(Fore.RED + " New File" + Style.RESET_ALL)


if __name__ == "__main__":
    main()
