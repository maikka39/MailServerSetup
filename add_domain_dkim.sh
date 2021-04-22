#!/bin/sh

domain=$(dialog --inputbox "Please enter your domain name.\\nEx. example.com" 10 60 3>&1 1>&2 2>&3 3>&1) || exit 1

# To add domains to OpenDKIM:
mkdir -p /etc/postfix/dkim/keys/$domain/
opendkim-genkey -r -D /etc/postfix/dkim/keys/$domain/ -d $domain
chgrp -R opendkim /etc/postfix/dkim/keys/$domain/
chmod -R g+r /etc/postfix/dkim/keys/$domain/
echo "default._domainkey.$domain $domain:default:/etc/postfix/dkim/keys/$domain/default.private" >> /etc/postfix/dkim/keytable
echo "*@$domain default._domainkey.$domain" >> /etc/postfix/dkim/signingtable

for x in opendkim postfix; do
	printf "Restarting %s..." "$x"
	systemctl restart "$x" && printf " ...done\\n"
done

pval="$(tr -d "\n" </etc/postfix/dkim/keys/$domain/default.txt | sed "s/k=rsa.* \"p=/k=rsa; p=/;s/\"\s*\"//;s/\"\s*).*//" | grep -o "p=.*")"
dkimentry="default._domainkey.$domain	TXT	v=DKIM1; k=rsa; $pval"
echo "$dkimentry"
# Put the output of that into dns at a TXT record for default._domainkey
