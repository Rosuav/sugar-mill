cd `dirname $0`
exec 3<>db.rosuav.com.key
while read line; do
	[ "$line" == '-----BEGIN CERTIFICATE-----' ] && exec 3>&- && exec 3<>db.rosuav.com.pem
	echo $line >&3
done
exec 3>&-
chmod 400 db.rosuav.com.key
./deploy
