# Put this script on Gideon in /root
exec 3<>db.rosuav.com.pem
while read line; do
	[ "$line" == '-----BEGIN PRIVATE KEY-----' ] && exec 3>&- && exec 3<>db.rosuav.com.key
	echo $line >&3
done
exec 3>&-
cp db.rosuav.com.* /home/rosuav/stillebot/
chown rosuav: /home/rosuav/stillebot/db.rosuav.com.*
cp db.rosuav.com.* /etc/postgresql/16/main/
chown postgres: /etc/postgresql/16/main/db.rosuav.com.*
systemctl reload postgresql
