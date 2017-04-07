# x509tosaml: SAML 2.0 IdP based on X.509

Very simple SAML 2.0 Identity Provider (IdP) based on TLS client authentication.  The Subject DN from a users' personal X.509 certificate is mapped onto SAML attributes.

This is an Open IdP, meaning that no SAML 2.0 SP metadata registration is necessary. 

Please note that this is not a conforming SAML implementation. It will not work with all SAML software implementations. It has been tested with [simpleSAMLphp](http://simplesamlphp.org).


# Installation

This software is implemented using PHP. It relies on a web server for handling TLS authentication. Currently, [Apache httpd](https://httpd.apache.org) is used, but it should also work with other web servers such as [nginx](http://nginx.org).

## Server

Manual installation is straightforward, but easier using [Ansible](https://www.ansible.com). See the ansible [playbook](/ansible/playbook.yml). Note that the playbook file is written for [debian](https://www.debian.org)-based linux systems.

A [Vagrant](https://www.vagrantup.com) is supplied for an [Ubuntu 16.04 LTS](http://releases.ubuntu.com/16.04/) (Xenial Xerus) system to easily fire up a VM.

## Software

The Vagrant VM runs the PHP application directly from a shared folder (`/vagrant/www`), so no installation is necessary.

For other systems, the PHP server needs to be installed manually using [Composer](https://getcomposer.org). follow the instructions on their web site for a safe way to [install composer](https://getcomposer.org/download/). On Ubuntu:

	$ apt-get install git php-zip composer

With composer installed, clone and install the PHP application at a suitable location (e.g. `/opt`) using:

	$ git clone https://github.com/joostd/x509tosaml.git
	$ cd x509tosaml
	$ composer install
	
	
# Configuration

The server does not need any configuration to run. However, you will probably need to tweak configuration a bit for the server to be useful.

## Server certificate

By default, the server is deployed using a self-signed certificate. You should replace this certificate with a "real" certificate trusted by current browsers.

You can easily get a server certificate from [let's encrypt](https://letsencrypt.org). For Apache on Ubuntu 16.04 for instance, [use these certbot instructions](https://certbot.eff.org/#ubuntuxenial-apache).

## SAML signing certificate

By default, SAML assertions are unsigned. SAML Service Provicers will not trust unsigned assertions, so you will need to generate a SAML signing certificate, as follows:

	$ cd samltox509
	$ openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem  \
		-subj '/CN=SAML signing' -days 3650 -out cert.pem
	
Also generate a DER-encoded version of this certificate (included in metadata):

	$ openssl x509 -in cert.pem -outform der -out cert.crt
	
## Trusted Certification Authorities

For TLS client authentication to work, your Apache webserver needs to have access to all intermediary or root certificates of the Certification Authorities (CAs) that issued client certificates. These are stored in `/etc/ssl/certs`.

If you need to support certificates issued by additional CAs, you will need to add the certificates of those CAs to that directory. For instance, to support [TCS personal certificates](https://www.terena.org/activities/tcs/repository/), download the intermediary CA certificate and rebuild the hash-based index using:

	$ wget https://www.terena.org/activities/tcs/repository-g3/TERENA_Personal_CA_3.pem
	$ sudo cp TERENA_Personal_CA_3.pem /etc/ssl/certs
	$ sudo /usr/bin/c_rehash

# Updates

To update the PHP application from its git repository:

	$ git pull

Then update its dependencies:

	$ composer update
	
# Security Considerations

Note that the provided ansible scripts are intended for automatic deployment of a test instance and are therefore minimal. Make sure you configure your server securely when connecting to the Internet. For instance, consider activating automatic updates. On Ubuntu:

	$ sudo apt-get install unattended-upgrades

Als note that the PHP application and its dependencies have to be upgraded manually.

# Advanced use

## Command line testing

To generate a SAML authentication request message, a test script is included:

	$ php test/request.php
	
This will print a URL to this IdP's SSOlocation (e.g. https://localhost/sso) with an encoded SAML AuthnRequest message.

To automatically open this URL in your browser, use something like (on e.g. osx):

	$ php test/request.php | xargs open -a Firefox

To view the response: use

	$ XPATH="//*[local-name()='input' and @type='hidden' and @name='SAMLResponse']/@value"
	$ php test/request.php | xargs curl -sk | xmllint --xpath "$XPATH" - | cut -d= -f2- | xargs | base64 -D | xmllint --format -

Use `curl`'s `-E` flag to supply a personal certificate.
