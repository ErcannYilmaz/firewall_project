#!/bin/bash

# Python 3.9'ı indirme ve kurma
apt-get update
apt-get install -y python3.9 python3-pip libpcap-dev hostapd isc-dhcp-server

pip install colorama numpy pandas scikit-learn joblib

cd PcapPlusPlus-22.11/
make all
make install


# İşlem tamamlandı
echo "Gerekli paketler başarıyla indirildi ve kuruldu."