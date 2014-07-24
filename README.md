x509tosaml
==========

Simple SAML 2.0 Identity Provider translating X.509 user certificates into SAML assertions

Software
--------

	sudo apt-get install apache2 php5
	sudo apt-get install git
	sudo apt-get install curl

SSL
---

	sudo a2enmod ssl

	sudo cp x509tosaml /etc/apache2/sites-available/
	sudo a2ensite x509tosaml 

Edit the file `/etc/apache2/sites-enabled/x509tosaml`

	SSLCertificateFile    /etc/ssl/certs/cert.pem
	SSLCertificateKeyFile /etc/ssl/private/key.key
	SSLCertificateChainFile /etc/ssl/certs/chain.pem

reload:

	sudo service apache2 reload


php
---

	curl -s https://getcomposer.org/installer | php
	php composer.phar require "silex/silex:~1.2"
	php composer.phar require "twig/twig:1.*"
	php composer.phar install
	php composer.phar update
