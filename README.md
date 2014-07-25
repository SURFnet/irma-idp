x509tosaml
==========

Simple SAML 2.0 Identity Provider translating X.509 user certificates into SAML assertions

Software Dependencies
---------------------

This software is written in php, and needs web server software to run on.
Apache web server is assumed.
NTP is needed to provide timestamps in SAML statements.

	sudo apt-get install apache2 php5
	sudo apt-get install ntp

SSL/TLS
---

SSL/TLS  is required for client authentication using X.509 user certificates.

For apache on a debian-based system:

	sudo a2enmod ssl

	sudo cp x509tosaml /etc/apache2/sites-available/
	sudo a2ensite x509tosaml 

You will need to provide a server certificate, its private key, and the CA chain.

For apache on a debian based system, edit the file `/etc/apache2/sites-enabled/x509tosaml`

	SSLCertificateFile    /etc/ssl/certs/cert.pem
	SSLCertificateKeyFile /etc/ssl/private/key.key
	SSLCertificateChainFile /etc/ssl/certs/chain.pem

After making changes, you will need to restart teh web server.

For apache on a debian based system:

	sudo service apache2 reload

php
---

	curl -s https://getcomposer.org/installer | php
	php composer.phar require "silex/silex:~1.2"
	php composer.phar require "twig/twig:1.*"
	php composer.phar install
	php composer.phar update
