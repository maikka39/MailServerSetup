#!/bin/sh

# On installation of Postfix, select "Internet Site" and put in TLD (without
# `mail.` before it).

echo "Installing programs..."
apt install dialog postfix postfix-mysql dovecot-core dovecot-imapd dovecot-sieve dovecot-lmtpd dovecot-mysql opendkim spamassassin spamc mariadb-server

# Check if OpenDKIM is installed and install it if not.
which opendkim-genkey >/dev/null 2>&1 || apt install opendkim-tools
domain="$(cat /etc/mailname)"
subdom=${MAIL_SUBDOM:-mail}
maildomain="$subdom.$domain"
certdir="/etc/letsencrypt/live/$maildomain"

[ ! -d "$certdir" ] && certdir="$(dirname "$(certbot certificates 2>/dev/null | grep "$maildomain\|*.$domain" -A 2 | awk '/Certificate Path/ {print $3}' | head -n1)")"

[ ! -d "$certdir" ] && echo "Note! You must first have a Let's Encrypt Certbot HTTPS/SSL Certificate for $maildomain.

Use Let's Encrypt's Certbot to get that and then rerun this script.

You may need to set up a dummy $maildomain site in nginx or Apache for that to work." && exit

echo "Configuring MySQL"
echo "Leave current password empty
Select no for set root password
Remove anonymous users
Disallow root login remotely
Remove test database and access to it
Reload privilege tables now"
mysql_secure_installation

echo "Creating database"
name=$(dialog --inputbox "Please enter a name for the first email address.\\nEx. maik" 10 60 3>&1 1>&2 2>&3 3>&1) || exit 1
pass1=$(dialog --no-cancel --passwordbox "Enter a password for that inbox." 10 60 3>&1 1>&2 2>&3 3>&1)
pass2=$(dialog --no-cancel --passwordbox "Retype password." 10 60 3>&1 1>&2 2>&3 3>&1)
while ! [ "$pass1" = "$pass2" ]; do
    unset pass2
	pass1=$(dialog --no-cancel --passwordbox "Passwords do not match.\\n\\nEnter password again." 10 60 3>&1 1>&2 2>&3 3>&1)
	pass2=$(dialog --no-cancel --passwordbox "Retype password." 10 60 3>&1 1>&2 2>&3 3>&1)
done

echo "\
CREATE DATABASE servermail;
GRANT SELECT ON servermail.* TO 'mail'@'127.0.0.1' IDENTIFIED BY 'superstrongpassword';
FLUSH PRIVILEGES;
USE servermail;

CREATE TABLE \`virtual_domains\` (
\`id\`  INT NOT NULL AUTO_INCREMENT,
\`name\` VARCHAR(50) NOT NULL,
PRIMARY KEY (\`id\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE \`virtual_users\` (
\`id\` INT NOT NULL AUTO_INCREMENT,
\`domain_id\` INT NOT NULL,
\`password\` VARCHAR(106) NOT NULL,
\`email\` VARCHAR(120) NOT NULL,
PRIMARY KEY (\`id\`),
UNIQUE KEY \`email\` (\`email\`),
FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE \`virtual_aliases\` (
\`id\` INT NOT NULL AUTO_INCREMENT,
\`domain_id\` INT NOT NULL,
\`source\` varchar(100) NOT NULL,
\`destination\` varchar(100) NOT NULL,
PRIMARY KEY (\`id\`),
FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO \`servermail\`.\`virtual_domains\`
(\`id\`, \`name\`)
VALUES
('1', '$domain');

INSERT INTO \`servermail\`.\`virtual_users\`
(\`id\`, \`domain_id\`, \`password\` , \`email\`)
VALUES
('1', '1', ENCRYPT('$pass1', CONCAT('\$6\$', SUBSTRING(SHA(RAND()), -16))), '$name@$domain');

INSERT INTO \`servermail\`.\`virtual_aliases\`
(\`id\`, \`domain_id\`, \`source\`, \`destination\`)
VALUES
('1', '1', 'example@$domain', '$name@$domain');
" | mysql -u root


# NOTE ON POSTCONF COMMANDS

# The `postconf` command literally just adds the line in question to
# /etc/postfix/main.cf so if you need to debug something, go there. It replaces
# any other line that sets the same setting, otherwise it is appended to the
# end of the file.

echo "Configuring Postfix's main.cf..."

# Change the cert/key files to the default locations of the Let's Encrypt cert/key
postconf -e "smtpd_tls_key_file=$certdir/privkey.pem"
postconf -e "smtpd_tls_cert_file=$certdir/fullchain.pem"
postconf -e "smtpd_tls_security_level = may"
postconf -e "smtpd_tls_auth_only = yes"
postconf -e "smtp_tls_security_level = may"
postconf -e "smtp_tls_loglevel = 1"
postconf -e "smtp_tls_CAfile=$certdir/cert.pem"
postconf -e "smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
postconf -e "smtp_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
postconf -e "smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
postconf -e "smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
postconf -e "tls_preempt_cipherlist = yes"
postconf -e "smtpd_tls_exclude_ciphers = aNULL, LOW, EXP, MEDIUM, ADH, AECDH, MD5, DSS, ECDSA, CAMELLIA128, 3DES, CAMELLIA256, RSA+AES, eNULL"

# Here we tell Postfix to look to Dovecot for authenticating users/passwords.
# Dovecot will be putting an authentication socket in /var/spool/postfix/private/auth
postconf -e "smtpd_sasl_auth_enable = yes"
postconf -e "smtpd_sasl_type = dovecot"
postconf -e "smtpd_sasl_path = private/auth"

# Sender and recipient restrictions
postconf -e "smtpd_recipient_restrictions = permit_sasl_authenticated, permit_mynetworks, reject_unauth_destination"

postconf -e "mydestination = localhost"
postconf -e "myhostname = $maildomain"

postconf -e "virtual_transport = lmtp:unix:private/dovecot-lmtp"

postconf -e "virtual_mailbox_domains = mysql:/etc/postfix/mysql-virtual-mailbox-domains.cf"
postconf -e "virtual_mailbox_maps = mysql:/etc/postfix/mysql-virtual-mailbox-maps.cf"
postconf -e "virtual_alias_maps = mysql:/etc/postfix/mysql-virtual-alias-maps.cf"

echo "user = mail
password = superstrongpassword
hosts = 127.0.0.1
dbname = servermail
query = SELECT 1 FROM virtual_domains WHERE name='%s'" > /etc/postfix/mysql-virtual-mailbox-domains.cf

echo "user = mail
password = superstrongpassword
hosts = 127.0.0.1
dbname = servermail
query = SELECT 1 FROM virtual_users WHERE email='%s'" > /etc/postfix/mysql-virtual-mailbox-maps.cf

echo "user = mail
password = superstrongpassword
hosts = 127.0.0.1
dbname = servermail
query = SELECT email FROM virtual_users WHERE email='%s' UNION SELECT destination FROM virtual_aliases WHERE source='%s' UNION SELECT destination FROM virtual_aliases WHERE source='*@%d' LIMIT 1" > /etc/postfix/mysql-virtual-alias-maps.cf



echo "Configuring Postfix's master.cf..."

sed -i "/^\s*-o/d;/^\s*submission/d;/^\s*smtp/d" /etc/postfix/master.cf

echo "smtp unix - - n - - smtp
smtp inet n - y - - smtpd
  -o content_filter=spamassassin
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=yes
smtps     inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
spamassassin unix -     n       n       -       -       pipe
  user=debian-spamd argv=/usr/bin/spamc -f -e /usr/sbin/sendmail -oi -f \${sender} \${recipient}" >> /etc/postfix/master.cf


# By default, dovecot has a bunch of configs in /etc/dovecot/conf.d/ These
# files have nice documentation if you want to read it, but it's a huge pain to
# go through them to organize.  Instead, we simply overwrite
# /etc/dovecot/dovecot.conf because it's easier to manage. You can get a backup
# of the original in /usr/share/dovecot if you want.

echo "Creating Dovecot config..."

echo "# Dovecot config
# Note that in the dovecot conf, you can use:
# %u for username
# %n for the name in name@domain.tld
# %d for the domain
# %h the user's home directory

# If you're not a brainlet, SSL must be set to required.
ssl = required
ssl_cert = <$certdir/fullchain.pem
ssl_key = <$certdir/privkey.pem
ssl_min_protocol = TLSv1.2
ssl_cipher_list = EECDH+ECDSA+AESGCM:EECDH+aRSA+AESGCM:EECDH+ECDSA+SHA256:EECDH+aRSA+SHA256:EECDH+ECDSA+SHA384:EECDH+ECDSA+SHA256:EECDH+aRSA+SHA384:EDH+aRSA+AESGCM:EDH+aRSA+SHA256:EDH+aRSA:EECDH:!aNULL:!eNULL:!MEDIUM:!LOW:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS:!RC4:!SEED
ssl_prefer_server_ciphers = yes
ssl_dh = </usr/share/dovecot/dh.pem

# Plaintext login. This is safe and easy thanks to SSL.
disable_plaintext_auth = yes
auth_mechanisms = plain login
auth_username_format = %u

!include conf.d/auth-sql.conf.ext

protocols = \$protocols imap lmtp

passdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}
userdb {
  driver = static
  args = uid=vmail gid=vmail home=/var/mail/vhosts/%d/%n
}

mail_privileged_group = mail

mail_location = maildir:/var/mail/vhosts/%d/%n
namespace inbox {
    inbox = yes
    mailbox Drafts {
        special_use = \\Drafts
        auto = subscribe
    }
    mailbox Junk {
        special_use = \\Junk
        auto = subscribe
        autoexpunge = 30d
    }
    mailbox Sent {
        special_use = \\Sent
        auto = subscribe
    }
    mailbox Trash {
        special_use = \\Trash
    }
    mailbox Archive {
        special_use = \\Archive
    }
}

service imap-login {
  inet_listener imap {
    port = 0
  }
}

service lmtp {
   unix_listener /var/spool/postfix/private/dovecot-lmtp {
	   mode = 0600
	   user = postfix
	   group = postfix
   }
}

# Here we let Postfix use Dovecot's authetication system.

service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }

  unix_listener auth-userdb {
    mode = 0600
    user = vmail
  }

  user = dovecot
}

service auth-worker {
  user = vmail
}

protocol lda {
  mail_plugins = \$mail_plugins sieve
}

protocol lmtp {
  mail_plugins = \$mail_plugins sieve
}

plugin {
	sieve = ~/.dovecot.sieve
	sieve_default = /var/lib/dovecot/sieve/default.sieve
	#sieve_global_path = /var/lib/dovecot/sieve/default.sieve
	sieve_dir = ~/.sieve
	sieve_global_dir = /var/lib/dovecot/sieve/
}
" > /etc/dovecot/dovecot.conf

echo "driver = mysql
connect = host=127.0.0.1 dbname=servermail user=mail password=superstrongpassword
default_pass_scheme = SHA512-CRYPT
password_query = SELECT email as user, password FROM virtual_users WHERE email='%u';" > /etc/dovecot/dovecot-sql.conf.ext


echo "Creating mail user..."

mkdir /var/lib/dovecot/sieve/

echo "require [\"fileinto\", \"mailbox\"];
if header :contains \"X-Spam-Flag\" \"YES\"
    {
        fileinto \"Junk\";
    }" > /var/lib/dovecot/sieve/default.sieve

groupadd -g 5000 vmail
useradd -g vmail -u 5000 vmail -d /var/mail
chown -R vmail:vmail /var/mail
chown -R vmail:vmail /var/lib/dovecot
chown -R vmail:dovecot /etc/dovecot
chmod -R o-rwx /etc/dovecot

sievec /var/lib/dovecot/sieve/default.sieve


# OpenDKIM

# A lot of the big name email services, like Google, will automatically reject
# as spam unfamiliar and unauthenticated email addresses. As in, the server
# will flatly reject the email, not even delivering it to someone's Spam
# folder.

# OpenDKIM is a way to authenticate your email so you can send to such services
# without a problem.

# Create an OpenDKIM key in the proper place with proper permissions.
echo "Generating OpenDKIM keys..."
mkdir -p /etc/postfix/dkim
opendkim-genkey -D /etc/postfix/dkim/ -d "$domain" -s "$subdom"
chgrp opendkim /etc/postfix/dkim/*
chmod g+r /etc/postfix/dkim/*

# Generate the OpenDKIM info:
echo "Configuring OpenDKIM..."
grep -q "$domain" /etc/postfix/dkim/keytable 2>/dev/null ||
echo "$subdom._domainkey.$domain $domain:$subdom:/etc/postfix/dkim/$subdom.private" >> /etc/postfix/dkim/keytable

grep -q "$domain" /etc/postfix/dkim/signingtable 2>/dev/null ||
echo "*@$domain $subdom._domainkey.$domain" >> /etc/postfix/dkim/signingtable

grep -q "127.0.0.1" /etc/postfix/dkim/trustedhosts 2>/dev/null ||
	echo "127.0.0.1
10.1.0.0/16
1.2.3.4/24" >> /etc/postfix/dkim/trustedhosts

# ...and source it from opendkim.conf
grep -q "^KeyTable" /etc/opendkim.conf 2>/dev/null || echo "KeyTable file:/etc/postfix/dkim/keytable
SigningTable refile:/etc/postfix/dkim/signingtable
InternalHosts refile:/etc/postfix/dkim/trustedhosts" >> /etc/opendkim.conf

sed -i '/^#Canonicalization/s/simple/relaxed\/simple/' /etc/opendkim.conf
sed -i '/^#Canonicalization/s/^#//' /etc/opendkim.conf

sed -e '/Socket/s/^#*/#/' -i /etc/opendkim.conf
grep -q "^Socket\s*inet:12301@localhost" /etc/opendkim.conf || echo "Socket inet:12301@localhost" >> /etc/opendkim.conf

# OpenDKIM daemon settings, removing previously activated socket.
sed -i "/^SOCKET/d" /etc/default/opendkim && echo "SOCKET=\"inet:12301@localhost\"" >> /etc/default/opendkim

# Here we add to postconf the needed settings for working with OpenDKIM
echo "Configuring Postfix with OpenDKIM settings..."
postconf -e "smtpd_sasl_security_options = noanonymous, noplaintext"
postconf -e "smtpd_sasl_tls_security_options = noanonymous"
postconf -e "myhostname = $maildomain"
postconf -e "milter_default_action = accept"
postconf -e "milter_protocol = 6"
postconf -e "smtpd_milters = inet:localhost:12301"
postconf -e "non_smtpd_milters = inet:localhost:12301"
postconf -e "mailbox_command = /usr/lib/dovecot/deliver"

for x in spamassassin opendkim dovecot postfix; do
	printf "Restarting %s..." "$x"
	systemctl restart "$x" && printf " ...done\\n"
done

pval="$(tr -d "\n" </etc/postfix/dkim/$subdom.txt | sed "s/k=rsa.* \"p=/k=rsa; p=/;s/\"\s*\"//;s/\"\s*).*//" | grep -o "p=.*")"
dkimentry="$subdom._domainkey.$domain	TXT	v=DKIM1; k=rsa; $pval"
dmarcentry="_dmarc.$domain	TXT	v=DMARC1; p=reject; rua=mailto:dmarc@$domain; fo=1"
spfentry="@	TXT	v=spf1 mx a:$maildomain -all"

useradd -m -G mail dmarc

echo "$dkimentry
$dmarcentry
$spfentry" > "$HOME/dns_setupmail.txt"

printf "\033[31m
 _   _
| \ | | _____      ___
|  \| |/ _ \ \ /\ / (_)
| |\  | (_) \ V  V / _
|_| \_|\___/ \_/\_/ (_)\033[0m

Add these three records to your DNS TXT records on either your registrar's site
or your DNS server:
\033[32m
$dkimentry

$dmarcentry

$spfentry
\033[0m
NOTE: You may need to omit the \`.$domain\` portion at the beginning if
inputting them in a registrar's web interface.

Also, these are now saved to \033[34m~/dns_setupmail.txt\033[0m in case you want them in a file.
"
