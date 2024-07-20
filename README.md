## Magicspoofmail

Magic Spoof Mail 1.0 is a Python script designed to check domain configurations for SPF and DMARC records, and to test email spoofing capabilities. The script allows sending spoofed emails to test the security of domain configurations and includes functionalities for attaching files, using custom SMTP servers, and more.

### Prerequisites

- Python 3.x
- Postfix mail server
- Required Python packages:
  - argparse
  - dkimpy (for DKIM signing)
  - pydig (for DNS queries)
  - smtplib (for sending emails)
  - email (for creating email messages)

* * *

## Installation

### Install Postfix

If Postfix is not installed, you can install it using the following commands:

**For Debian/Ubuntu:**

```bash
sudo apt-get update
sudo apt-get install postfix -y
```

**For CentOS/RHEL:**

```bash
sudo yum install postfix -y
```

**For Fedora:**

```bash
sudo dnf install postfix -y
```

After installing Postfix, start and enable the service:

```bash
sudo systemctl start postfix
sudo systemctl enable postfix
```

**Clone the repository**

```bash
git clone https://github.com/neoslab/magicspoofmail
```

**Change to the project directory**

```bash
cd magicspoofmail
```

**Install the required libraries**

```bash
python -m pip install -r requirements.txt
```

* * *

## Script Usage

### Command-line Arguments

The script accepts the following command-line arguments:

- `-f, --file`: File with a list of domains to check.
- `-d, --domain`: Single domain to check.
- `-c, --common`: Check common TLDs.
- `-t, --test`: Send a test email.
- `-e, --email`: Receiver email address for the test email.
- `-s, --smtp`: Custom SMTP server to send the test email. Default: 127.0.0.1.
- `-a, --attachment`: Path to the file to attach with the email.
- `--subject`: Subject of the email message.
- `--template`: HTML template for the email body.
- `--sender`: Sender email address. Default: <test@domain.tld>.

### Examples

**Check a Single Domain:**

```bash
python magicspoofmail.py --domain example.com
```

**Check a List of Domains:**

```bash
python magicspoofmail.py --file domains.txt
```

**Check a Domain and Common TLDs:**

```bash
python magicspoofmail.py --domain example --common
```

**Send a Test Email:**

```bash
python magicspoofmail.py --domain example.com --test --email receiver@example.com
```

**Send a Test Email with Attachment:**

```bash
python magicspoofmail.py --domain example.com --test --email receiver@example.com --attachment /path/to/file
```

**Send a Test Email Using Custom SMTP Server:**

```bash
python magicspoofmail.py --domain example.com --test --email receiver@example.com --smtp smtp.example.com
```

### Script Functionality

- **check_spf(domain)**: Checks if a domain has SPF configuration.
- **check_dmarc(domain)**: Checks if a domain has DMARC configuration.
- **spoof(domain, you, smtpserv)**: Sends a spoofed email from a specified domain.
- **send_email(domain, destination, smtpserv, dkim_private_key_path, dkim_selector)**: Sends an email with optional DKIM signing.
- **start(domain)**: Starts the analysis for a specified domain.
- **create_backup()**: Creates a backup of the Postfix `main.cf` file.
- **restore_backup()**: Restores the Postfix `main.cf` file from the backup.

### Backup and Restore Postfix Configuration

Before modifying the Postfix `main.cf` file, the script creates a backup of the file. Once the script has finished running, it restores the original configuration and reloads the Postfix service to apply the changes.

* * *

### Acknowledgements

This script is based on [https://github.com/magichk/magicspoofing](https://github.com/magichk/magicspoofing).