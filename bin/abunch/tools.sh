#!/bin/bash

###################################################################
#Description	: Script for install tools for android reversing
# 		  Testing in Ubuntu 20.04
# 		  Run as root 
#			Tools:
#				- APKtool
#				- Jadx
#				- adb 
#				- Java 8 
#				- sqlitebrowser
#				- Docker
#				- Mobsf from Docker 
#				- Frida 
#				- Pidcat 
#Author       	: Cristian Cantos
###################################################################


# Check if run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi


# Update apt
apt-get update -y


# Install sqlitebrowser
sqlitebrowserInstall(){
	dpkg -s sqlitebrowser &> /dev/null
	if [ $? -ne 0 ]; then
        	echo "[INFO ] Installing Sqlitebrowser..."
	        apt install sqlitebrowser  -y
	else
        	echo "[ERROR] Sqlitebrowser is already installed..."
	fi
}


# Install ADB
adbInstall(){
	dpkg -s adb &> /dev/null
	if [ $? -ne 0 ]; then
        	echo "[INFO ] Installing adb..."
	        apt install adb  -y
	else
        	echo "[ERROR] adb is already installed..."
	fi
}


# Install JAVA 
javaInstall(){
	java -version &> /dev/null
	if [ $? -ne 0 ]; then
        	echo "[INFO ] Installing java..."
	        apt install openjdk-11-jre -y
	else
	        echo "[ERROR] Java is already installed..."
	fi
}


# Install JADX
jadxInstall(){
	JADX_VERSION=$(curl -s "https://api.github.com/repos/skylot/jadx/releases/latest" | grep -Po '"tag_name": "v\K[0-9.]+')
	jadx --version &> /dev/null
	if [ $? -ne 0 ]; then
	        echo "[INFO ] Installing JADX..."
	        wget  https://github.com/skylot/jadx/releases/download/v$JADX_VERSION/jadx-$JADX_VERSION.zip
	        mv jadx-$JADX_VERSION.zip /usr/local/bin/jadx-$JADX_VERSION.zip
	        unzip /usr/local/bin/jadx-$JADX_VERSION.zip -d /usr/local/bin/jadx-$JADX_VERSION
	        rm /usr/local/bin/jadx-$JADX_VERSION.zip
	        ln -s /usr/local/bin/jadx-$JADX_VERSION/bin/jadx /usr/local/bin/jadx
	        ln -s /usr/local/bin/jadx-$JADX_VERSION/bin/jadx-gui /usr/local/bin/jadx-gui
	else
	        echo "[ERROR] Jadx is already installed..."
	fi
}


# Install APKTOOL
apktoolInstall(){
	APKTOOL_VERSION=$(curl -s "https://api.github.com/repos/iBotPeaches/Apktool/releases/latest"| grep -Po '"tag_name": "v\K[0-9.]+')
	apktool -version &> /dev/null
	if [ $? -ne 0 ]; then
	       echo "[INFO ] Installing APKTOOL..."
	       wget  https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
	       wget  https://github.com/iBotPeaches/Apktool/releases/download/v$APKTOOL_VERSION/apktool_$APKTOOL_VERSION.jar
	       mv apktool_$APKTOOL_VERSION.jar apktool.jar
	       mv apktool.jar /usr/local/bin
	       mv apktool /usr/local/bin
	       chmod +x /usr/local/bin/apktool.jar
	       chmod +x /usr/local/bin/apktool
	else
        	echo "[ERROR] APKtool is already installed..."
	fi
}


# Install DOCKER
dockerInstall(){
	dpkg -s docker &> /dev/null
	if [ $? -ne 0 ]; then
        	echo "[INFO ] Installing Docker..."
        	apt install docker docker.io docker-compose  -y
	else
        	echo "[ERROR] Docker is already installed..."
	fi
}


# Install MOBSF from Docker
mobsfInstall(){
	echo "[INFO ] Downloads Docker Mobsf"
	docker pull opensecurity/mobile-security-framework-mobsf
	echo "[INFO ] FOR RUN DOCKER MOBSF ---> sudo docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest"
	echo "[INFO ] More info https://mobsf.github.io/docs/#/docker"
	echo "alias mobsf='sudo docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest'" >> ~/.bashrc
}


# Install PIDCAT
pidcatInstall(){
	pidcat --version &> /dev/null
	if [ $? -ne 0 ]; then
	        echo "[INFO ] Installing Pidcat..."
		wget https://raw.githubusercontent.com/JakeWharton/pidcat/master/pidcat.py
		sed '1 d' pidcat.py > pidcat_tmp
		sed '1 i\#!\/usr\/bin\/python3' pidcat_tmp > pidcat
		mv pidcat /etc/
		chmod +x /etc/pidcat
		ln -s /etc/pidcat /usr/bin/pidcat
	else
	        echo "[ERROR] Pidcat is already installed..."
	fi
}


# Install FRIDA
fridaInstall(){
	frida --version &> /dev/null
	if [ $? -ne 0 ]; then
        	echo "[INFO ] Installing Frida..."
	        pip3 install frida-tools
		if [ $? -ne 0 ]; then
			apt install python3 -y
			apt install python3-pip -y
			pip3 install frida-tools
		fi
	else
        	echo "[ERROR] Frida is already installed..."
	fi
}


apktoolInstall
jadxInstall
javaInstall
adbInstall
sqlitebrowserInstall
dockerInstall
mobsfInstall
pidcatInstall
fridaInstall