# Mail server setup script

This script automates the grueling process of installing and setting up
an email server. It perfectly reproduces my successful steps to ensure the
same setup time and time again, now with many improvements.

When prompted by a dialog menu at the beginning, select "Internet Site", then
give your full domain without any subdomain, i.e. `example.com`.

## Logging in from a mail client

Let's say you want to access your mail with Thunderbird or mutt or another
email program. The server information will be as follows:

- SMTP server: `mail.example.com`
- SMTP port: 587
- IMAP server: `mail.example.com`
- IMAP port: 993

## Troubleshooting -- Can't send mail?

- Always check `journalctl -xe` to see the specific problem.
- Go to [this site](https://appmaildev.com/en/dkim) to test your TXT records.
  If your DKIM, SPF or DMARC tests fail you probably copied in the TXT records
  incorrectly.
- If everything looks good and you *can* send mail, but it still goes to Gmail
  or another big provider's spam directory, your domain (especially if it's a
  new one) might be on a public spam list.  Check
  [this site](https://mxtoolbox.com/blacklists.aspx) to see if it is. Don't
  worry if you are: sometimes especially new domains are automatically assumed
  to be spam temporarily. If you are blacklisted by one of these, look into it
  and it will explain why and how to remove yourself.
- Check your DNS settings using [this site](https://intodns.com/), it'll report
  any issues with your MX records
- Ensure that port 25 is open on your server.
  [Vultr](https://www.vultr.com/docs/what-ports-are-blocked) for instance
  blocks this by default, you need to open a support ticket with them to open
  it. You can't send mail if 25 is blocked
