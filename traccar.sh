#! /bin/sh

# Version 0.5
# This is a startup script for traccar
# Based on UniFi Controller on Debian for  https://metis.fi/en/2018/02/unifi-on-gcp/ v1.3.3
#
# You may use this as you see fit as long as I am credited for my work.
# (c) 2018 Petri Riihikallio Metis Oy
# (c) 2019 Jonathan Dixon

###########################################################
#
# Set up logging for unattended scripts and UniFi's MongoDB log
# Variables $LOG  used later on in the script.
#
LOG="/var/log/unifi/gcp-traccar.log"
if [ ! -f /etc/logrotate.d/traccar-unifi.conf ]; then
	cat > /etc/logrotate.d/traccar-unifi.conf <<_EOF
$LOG {
	monthly
	rotate 4
	compress
}
_EOF
	echo "Script logrotate set up"
fi


###########################################################
#
# Turn off IPv6 for now
#
if [ ! -f /etc/sysctl.d/20-disableIPv6.conf ]; then
	echo "net.ipv6.conf.all.disable_ipv6=1" > /etc/sysctl.d/20-disableIPv6.conf
	sysctl --system > /dev/null
	echo "IPv6 disabled"
fi

###########################################################
#
# Update DynDNS as early in the script as possible
#
ddns=$(curl -fs -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/ddns-url")
if [ ${ddns} ]; then
	curl -fs ${ddns}
	echo "Dynamic DNS accessed"
fi

###########################################################
#
# Create a swap file for small memory instances and increase /run
#
if [ ! -f /swapfile ]; then
	memory=$(free -m | grep "^Mem:" | tr -s " " | cut -d " " -f 2)
	echo "${memory} megabytes of memory detected"
	if [ -z ${memory} ] || [ "0${memory}" -lt "2048" ]; then
		fallocate -l 2G /swapfile
		chmod 600 /swapfile
		mkswap /swapfile >/dev/null
		swapon /swapfile
		echo '/swapfile none swap sw 0 0' >> /etc/fstab
		echo 'tmpfs /run tmpfs rw,nodev,nosuid,size=400M 0 0' >> /etc/fstab
		mount -o remount,rw,nodev,nosuid,size=400M tmpfs /run
		echo "Swap file created"
	fi
fi

###########################################################
#
# Add backports if it doesn't exist
#
release=$(lsb_release -a 2>/dev/null | grep "^Codename:" | cut -f 2)
if [ ${release} ] && [ ! -f /etc/apt/sources.list.d/backports.list ]; then
	cat > /etc/apt/sources.list.d/backports.list <<_EOF
deb http://deb.debian.org/debian/ ${release}-backports main
deb-src http://deb.debian.org/debian/ ${release}-backports main
_EOF
	echo "Backports (${release}) added to APT sources"
fi

###########################################################
#
# Install stuff
#

# Required preliminiaries
if [ ! -f /usr/share/misc/apt-upgraded-1 ]; then
	export APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=DontWarn    # For CGP packages
	curl -Lfs https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -    # For CGP packages
	apt-get -qq update -y >/dev/null
	DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade -y >/dev/null    # GRUB upgrades require special flags
	rm /usr/share/misc/apt-upgraded    # Old flag file
	touch /usr/share/misc/apt-upgraded-1
	echo "System upgraded"
fi

# HAVEGEd is straightforward
haveged=$(dpkg-query -W --showformat='${Status}\n' haveged 2>/dev/null)
if [ "x${haveged}" != "xinstall ok installed" ]; then 
	if apt-get -qq install -y haveged >/dev/null; then
		echo "Haveged installed"
	fi
fi

certbot=$(dpkg-query -W --showformat='${Status}\n' certbot 2>/dev/null)
if [ "x${certbot}" != "xinstall ok installed" ]; then
if (apt-get -qq install -y -t ${release}-backports certbot >/dev/null) || (apt-get -qq install -y certbot >/dev/null); then
		echo "CertBot installed"
	fi
fi

f2b=$(dpkg-query -W --showformat='${Status}\n' fail2ban 2>/dev/null)
if [ "x${f2b}" != "xinstall ok installed" ]; then 
	if apt-get -qq install -y fail2ban >/dev/null; then
			echo "Fail2Ban installed"
	fi
fi

apt-get -qq  install -y  apache2

###########################################################
#
# Set the time zone
#
tz=$(curl -fs -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/timezone")
if [ ${tz} ] && [ -f /usr/share/zoneinfo/${tz} ]; then
	apt-get -qq install -y dbus >/dev/null
	if ! systemctl start dbus; then
		echo "Trying to start dbus"
		sleep 15
		systemctl start dbus
	fi
	if timedatectl set-timezone $tz; then echo "Localtime set to ${tz}"; fi
	systemctl reload-or-restart rsyslog
fi

###########################################################
#
# Set up unattended upgrades after 04:00 with automatic reboots
#
if [ ! -f /etc/apt/apt.conf.d/51unattended-upgrades-unifi ]; then
	cat > /etc/apt/apt.conf.d/51unattended-upgrades-unifi <<_EOF
Acquire::AllowReleaseInfoChanges "true";
Unattended-Upgrade::Origins-Pattern {
	"o=Debian,a=stable";
	"c=ubiquiti";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
_EOF

	cat > /etc/systemd/system/timers.target.wants/apt-daily-upgrade.timer <<_EOF
[Unit]
Description=Daily apt upgrade and clean activities
After=apt-daily.timer
[Timer]
OnCalendar=4:00
RandomizedDelaySec=30m
Persistent=true
[Install]
WantedBy=timers.target
_EOF
	systemctl daemon-reload
	systemctl reload-or-restart unattended-upgrades
	echo "Unattended upgrades set up"
fi

###########################################################
#
# Set up daily backup to a bucket after 01:00
#


bucket=$(curl -fs -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/bucket")
if [ ${bucket} ]; then
	cat > /usr/local/sbin/traccar_data_backup.sh <<_EOF
#! /bin/sh
systemctl stop traccar.service
# TODO: add the -d option to rsync, if we have versioning enabled on the bucket
/usr/bin/gsutil -m rsync -r /opt/traccar/data gs://$bucket
systemctl start traccar.service

_EOF

	cat > /etc/systemd/system/unifi-backup.service <<_EOF
[Unit]
Description=Daily backup to ${bucket} service
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=sh /usr/local/sbin/traccar_data_backup.sh
_EOF

	cat > /etc/systemd/system/unifi-backup.timer <<_EOF
[Unit]
Description=Daily backup to ${bucket} timer
[Timer]
OnCalendar=1:00
RandomizedDelaySec=30m
[Install]
WantedBy=timers.target
_EOF
	systemctl daemon-reload
	systemctl start unifi-backup.timer
	echo "Backups to ${bucket} set up"
fi


###########################################################
#
# Set up Let's Encrypt
#
dnsname=$(curl -fs -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/dns-name")
if [ -z ${dnsname} ]; then exit 0; fi
privkey=/etc/letsencrypt/live/${dnsname}/privkey.pem
pubcrt=/etc/letsencrypt/live/${dnsname}/cert.pem
chain=/etc/letsencrypt/live/${dnsname}/chain.pem
caroot=/usr/share/misc/ca_root.pem

# Write the cross signed root certificate to disk
if [ ! -f $caroot ]; then
	cat > $caroot <<_EOF
-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow
PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD
Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O
rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq
OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b
xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw
7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD
aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG
SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69
ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr
AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz
R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5
JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo
Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ
-----END CERTIFICATE-----
_EOF
fi

# Write pre and post hooks to stop Apache2 for the renewal
if [ ! -d /etc/letsencrypt/renewal-hooks/pre ]; then
	mkdir -p /etc/letsencrypt/renewal-hooks/pre
fi
cat > /etc/letsencrypt/renewal-hooks/pre/apache2 <<_EOF
#! /bin/sh
service apache2 stop
_EOF
chmod a+x /etc/letsencrypt/renewal-hooks/pre/apache2

if [ ! -d /etc/letsencrypt/renewal-hooks/post ]; then
	mkdir -p /etc/letsencrypt/renewal-hooks/post
fi
cat > /etc/letsencrypt/renewal-hooks/post/apache2 <<_EOF
#! /bin/sh
service apache2 start
_EOF
chmod a+x /etc/letsencrypt/renewal-hooks/post/apache2

# Write a script to acquire the first certificate (for a systemd timer)
cat > /usr/local/sbin/certbotrun.sh <<_EOF
#! /bin/sh

echo >> $LOG
echo "CertBot run on \$(date)" >> $LOG
	if [ ! -d /etc/letsencrypt/live/${dnsname} ]; then
                systemctl stop apache2
		if certbot certonly -d $dnsname --standalone --agree-tos --register-unsafely-without-email >> $LOG; then
			echo "Received certificate for ${dnsname}" >> $LOG
		fi
                systemctl start apache2
	fi
	if /etc/letsencrypt/renewal-hooks/deploy/unifi; then
		systemctl stop certbotrun.timer
		echo "Certificate installed for ${dnsname}" >> $LOG
	fi
else
	echo "No action because ${dnsname} doesn't resolve to ${extIP}" >> $LOG
fi
_EOF
chmod a+x /usr/local/sbin/certbotrun.sh

# Write the systemd unit files
if [ ! -f /etc/systemd/system/certbotrun.timer ]; then
	cat > /etc/systemd/system/certbotrun.timer <<_EOF
[Unit]
Description=Run CertBot hourly until success
[Timer]
OnCalendar=hourly
RandomizedDelaySec=15m
[Install]
WantedBy=timers.target
_EOF
	systemctl daemon-reload

	cat > /etc/systemd/system/certbotrun.service <<_EOF
[Unit]
Description=Run CertBot hourly until success
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/certbotrun.sh
_EOF
fi

# Start the above
if [ ! -d /etc/letsencrypt/live/${dnsname} ]; then
	if ! /usr/local/sbin/certbotrun.sh; then
		echo "Installing hourly CertBot run"
		systemctl start certbotrun.timer
	fi
fi


# Joth additions-------
# 1/ Use $dnsname in the redirect, rather than the requested hostname, to ensure navigation to
# IP address goes to the intended URL
# TODO: also redirect port 443 HTTPS. (currently it's not binding to that port at all)
# -- done above

# 2/ Enable stackdriver logging and monitoring

mkdir -p /etc/google-fluentd/config.d/

cat > /etc/google-fluentd/config.d/unifi.conf <<_EOF
<source>
  @type tail

  format none
  path /usr/lib/unifi/logs/*.log
  pos_file /var/lib/google-fluentd/pos/unifi.pos
  read_from_head true
  tag unifi
</source>
_EOF


if [ ! -f install-logging-agent.sh ] ; then 
	curl -sSO https://dl.google.com/cloudagents/install-logging-agent.sh
	sudo bash install-logging-agent.sh
fi

if [ ! -f install-monitoring-agent.sh ] ; then 
	curl -sSO https://dl.google.com/cloudagents/install-monitoring-agent.sh
	sudo bash install-monitoring-agent.sh
fi

echo "Installed Stackdriver logging and monitoring agents"

# 3/ Install handy utils

apt install less

# 4/ Apache rev TLS proxy
# from https://www.traccar.org/secure-connection/

a2enmod ssl
a2enmod proxy
a2enmod proxy_http
a2enmod proxy_wstunnel
a2enmod rewrite
a2dissite 000-default

cat > /etc/apache2/sites-available/traccar.conf <<_EOF

<IfModule mod_ssl.c>
        <VirtualHost _default_:443>

                ServerName ${dnsname}
                ServerAdmin webmaster@localhost

                DocumentRoot /var/www/html

                ProxyPass /api/socket ws://localhost:8082/api/socket enablereuse=off
                ProxyPassReverse /api/socket ws://localhost:8082/api/socket enablereuse=off

                ProxyPass / http://localhost:8082/ enablereuse=off
                ProxyPassReverse / http://localhost:8082/ enablereuse=off

                SSLEngine on
                SSLCertificateFile          /etc/letsencrypt/live/${dnsname}/fullchain.pem
                SSLCertificateKeyFile       /etc/letsencrypt/live/${dnsname}/privkey.pem

        </VirtualHost>
</IfModule>

<VirtualHost *:80>
  ServerName ${dnsname}
  Redirect / https://${dnsname}
</VirtualHost>

_EOF

a2ensite traccar
service apache2 restart


