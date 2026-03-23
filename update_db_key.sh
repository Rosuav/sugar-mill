cd `dirname $0`
exec 3<>db.rosuav.com.pem
while read line; do
	[ "$line" == '-----BEGIN RSA PRIVATE KEY-----' ] && exec 3>&- && exec 3<>db.rosuav.com.key
	echo $line >&3
done
exec 3>&-
./deploy
