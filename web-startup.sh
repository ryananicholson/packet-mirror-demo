#!/bin/bash

# Install Apache
sudo apt-get update
sudo apt-get install -y apache2
cat <<EOF > /var/www/html/index.html
<html><body><h1>Go Away</h1>
</body></html>
EOF

cat <<EOF > /var/www/html/admin.php
<html><body><h1>Welcome admin!</h1>
</body></html>
EOF

cat << EOF > /etc/apache2/sites-available/000-default.conf
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
    <Location /admin.php>
        Deny from all
        AuthUserFile /etc/apache2/.htpasswd
        AuthName "Restricted Area"
        AuthType Basic
        Satisfy Any
        require valid-user
    </Location>
</VirtualHost>
EOF

sudo sh -c 'echo "admin" | htpasswd -ic /etc/apache2/.htpasswd admin'
sudo systemctl restart apache2

# Wait for other web server to come up
sudo sed -i "s/localhost$/localhost\ $(hostname)/g" /etc/hosts
sleep 60

# Create iptables rules so we can see the traffic in packet mirror
sudo sed -i 's/#net\.ipv4\.ip_forward=1/net\.ipv4\.ip_forward=1/g' /etc/sysctl.conf
sudo sysctl -p
MYIP=$(ifconfig ens4 | grep inet| awk '{print $2}' | head -1)
FIRSTTHREE=$(echo $MYIP | cut -d '.' -f1-3)
LASTOCT=$(expr $(echo $MYIP | cut -d '.' -f4) - 1)
TESTIP=$FIRSTTHREE"."$LASTOCT
OTHERWS=""
echo -e "test\n\n" | nc $TESTIP 80 -w1 >/dev/null
if [ $? -eq 0 ]; then
  OTHERWS=$TESTIP
fi

if ! [[ $OTHERWS == $TESTIP ]]; then
  LASTOCT=$(expr $(echo $MYIP | cut -d '.' -f4) + 1)
  TESTIP=$FIRSTTHREE"."$LASTOCT
  echo -e "test\n\n" | nc $TESTIP 80 -w1 >/dev/null
  if [ $? -eq 0 ]; then
    OTHERWS=$TESTIP
  fi
fi

sudo iptables -t nat -A PREROUTING -s 35.191.0.0/16 -p tcp --dport 80 -j DNAT --to-destination $OTHERWS
sudo iptables -t nat -A PREROUTING -s 130.211.0.0/22 -p tcp --dport 80 -j DNAT --to-destination $OTHERWS
sudo iptables -t nat -A POSTROUTING -j MASQUERADE
sudo iptables save