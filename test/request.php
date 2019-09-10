#!/usr/bin/env php
<?php
# generate IdP-initiated (unsollicited) SAML 2.0 Authentication Request
# See https://sptest.iamshowcase.com/testsp_metadata.xml
$issuer = "IAMShowcase";
$acs_url = "https://sptest.iamshowcase.com/acs";

# this IDP's SSO URL
$sso_url = "http://localhost:8080/sso";

$now = gmdate("Y-m-d\TH:i:s\Z", time());
$id = "_"; for ($i = 0; $i < 42; $i++ ) $id .= dechex( rand(0,15) );

$request = <<<XML
<samlp:AuthnRequest
  xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'
  xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'
  ID='$id'
  Version='2.0'
  IssueInstant='$now'
  Destination='$sso_url'
  AssertionConsumerServiceURL='$acs_url'
  ProtocolBinding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
>
<saml:Issuer>$issuer</saml:Issuer>
</samlp:AuthnRequest>
XML;

# use HTTP-Redirect binding
$query  = 'SAMLRequest=' . urlencode(base64_encode(gzdeflate($request)));
$location = "$sso_url?$query";

#header('Location: ' . $location);
echo($location);
