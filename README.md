# irma-idp: federated Identity Provider based on IRMA

Very simple Identity Provider (IdP) based on IRMA credentials with rudimentary support for SAML 2.0.  IRMA attributes are mapped onto SAML attributes.

This is an Open IdP, meaning that no SAML 2.0 SP metadata registration is necessary. 

Please note that this is not a conforming SAML implementation. It will not work with all SAML software implementations. It has been tested with [simpleSAMLphp](http://simplesamlphp.org).


# Installation

This software is implemented using PHP. It relies on a IRMA api server for disclosing IRMA attributes. Currently, [irmago](https://github.com/privacybydesign/irmago) is used.


## Software

The PHP server needs to be installed manually using [Composer](https://getcomposer.org). follow the instructions on their web site for a safe way to [install composer](https://getcomposer.org/download/). On Ubuntu:

	$ apt-get install git php-zip composer

With composer installed, clone and install the PHP application at a suitable location (e.g. `/opt`) using:

	$ git clone https://github.com/joostd/irma-idp.git
	$ cd irma-idp
	$ composer install
	
	
# Configuration

TO DO

## SAML signing certificate

By default, SAML assertions are unsigned. SAML Service Provicers will not trust unsigned assertions, so you will need to generate a SAML signing certificate, as follows:

	$ cd samltox509
	$ openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem  \
		-subj '/CN=SAML signing' -days 3650 -out cert.pem
	
Also generate a DER-encoded version of this certificate (included in metadata):

	$ openssl x509 -in cert.pem -outform der -out cert.crt

## IRMA JWT keys

For signing disclosing requests with JWT, an RSA key is required:

	$ openssl genrsa -out jwt_key.pem 2048

The corresponding public key can be extracted for exchange with the IRMA server:

	$ openssl rsa -pubout -in jwt_key.pem -out jwt_pubkey.pem

Also, to verify JWT responses, the public key of the IRMA server needs to be stored in a file `pubkey.pem`

	$ curl https://irmago.surfconext.nl/irmaserver/publickey > www/pubkey.pem

You should verify this key out of band in a production setting:

	$ openssl rsa -in www/pubkey.pem -pubin -noout -modulus

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

## Testing with a Service Provider

Note that the IRMA IdP does not need to be configered with SP metadata - it will accept authentication requests from any SP. The SP on the other hand will probably not accept any IdP, so if it wants to accept the X.509 IdP, it needs to import its metadata.

For example, when using [simpleSAMLphp](http://simplesamlphp.org) to implement the SP, one could use the following configuration (located in the file `metadata/saml20-remote-idp.php`):

	$metadata['https://irma-idp.example.org/metadata'] = array (
	  'entityid' => 'https://irma-idp.example.org/metadata',
	  'name' => 'IRMA IdP',
	  'SingleSignOnService' => 'https://irma-idp.example.org/sso',
	  'certData' => 'MII...o=',
	);
	
`certData` contains the signing certificate generated for the IdP in base64 encoding. To generate this data, you can use:

	$ base64 < cert.crt

## Command line testing

To generate a SAML authentication request message, a test script is included:

	$ php test/request.php
	
This will print a URL to this IdP's SSOlocation (e.g. https://localhost/sso) with an encoded SAML AuthnRequest message.

To automatically open this URL in your browser, use something like (on e.g. macOS):

	$ php test/request.php | xargs open -a Firefox

This will send IRMA attributes to a [Simple Test Service Provider](https://sptest.iamshowcase.com/)
