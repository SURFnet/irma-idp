<?php
require_once __DIR__.'/../vendor/autoload.php';

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

define("KEYFILE", "../key.pem");
define("CERTFILE", "../cert.pem");      // PEM encoded version
define("CERTFILE_DER", "../cert.crt"); // DER encoded version

define("NAMEIDFORMAT", "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName");
define("AUTHNCONTEXTCLASSREF", "urn:oasis:names:tc:SAML:2.0:ac:classes:X509");

// TODO fix
date_default_timezone_set('Europe/Amsterdam');

function dn_attributes($dn) {
    $attributes = array();
    foreach( explode(',',$dn) as $pair ) {
	    if( $pair=='' ) continue;
        list($k, $v) = explode('=',$pair);
        $attributes[$k] = $v;
    }
    return $attributes;
}

function samlResponse($issuer, $destination, $audience, $requestID, $dn) {

    $now = gmdate("Y-m-d\TH:i:s\Z", time());
    $id = "_"; for ($i = 0; $i < 42; $i++ ) $id .= dechex( rand(0,15) ); // leave out?
    $notonorafter = gmdate("Y-m-d\TH:i:s\Z", time() + 60 * 5);
    $notbefore = gmdate("Y-m-d\TH:i:s\Z", time() - 30);

    $attributes = dn_attributes($dn);

    $loader = new Twig_Loader_Filesystem('views');
    $twig = new Twig_Environment($loader, array(
        'debug' => true,
    ));

    return $twig->render('AuthnResponse.xml', array(
        'ID' => $id,
        'Issuer' => $issuer,
        'IssueInstant' => $now,
        'Destination' => $destination,
        'Assertionid'	=> 'TODO',
        'Audience'	=> $audience,
        'InResponseTo'	=> $requestID,
        'NotBefore'	=> $notbefore,
        'NotOnOrAfter'	=> $notonorafter,
        'NameIDFormat' => NAMEIDFORMAT,
        'Subject'	=> $dn,
        'AuthnContextClassRef' => AUTHNCONTEXTCLASSREF,
        'attributes'	=> $attributes,
    ));
}

function utils_xml_create($xml, $preserveWhiteSpace = FALSE) {
        $dom = new DOMDocument();
        $dom->preserveWhiteSpace = $preserveWhiteSpace;
        $dom->loadXML($xml);
        $dom->formatOutput = TRUE;
        return $dom;
}

function utils_xml_sign($dom, $key, $cert = false)
{
    // remove whitespace without breaking signature
    $dom = utils_xml_create($dom->saveXML(), TRUE);
    $dsig = new XMLSecurityDSig();
    $dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
    $root = $dom->getElementsByTagName('Assertion')->item(0);
    assert('$root instanceof DOMElement');
    $insert_into = $dom->getElementsByTagName('Assertion')->item(0);
    $insert_before = $insert_into->getElementsByTagName('Subject')->item(0);
    $dsig->addReferenceList(array($root), XMLSecurityDSig::SHA1,
        array('http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N),
        array('id_name' => 'ID'));
    $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'private'));
    $objKey->loadKey($key);
    $dsig->sign($objKey);
    if ($cert)
        $dsig->add509Cert($cert, TRUE);
    $dsig->insertSignature($insert_into, $insert_before);
    return $dom;
}

$app = new Silex\Application(); 
$app['debug'] = true;

$app->register(new Silex\Provider\SessionServiceProvider());

$app->register(new Silex\Provider\TwigServiceProvider(), array(
    'twig.path' => __DIR__.'/views',
));

$app->get('/', function (Request $request) use ($app) {
    $url = $request->getUriForPath('/') . 'metadata';
    return "This is a SAML IDP<br/>See also the SAML 2.0 <a href='$url'>Metadata</a>";
});

$certfile = '../cert.pem';
$keyfile = '../key.pem';

########## SAML ##########

# SAML 2.0 Metadata

$app->get('/metadata', function (Request $request) use ($app) {
    $loader = new Twig_Loader_Filesystem('views');
    $twig = new Twig_Environment($loader, array(
    	'debug' => true,
    ));
    $base = $request->getUriForPath('/');
    $contents = file_get_contents(CERTFILE_DER);
    $certdata = $contents ? base64_encode($contents) : null;
    $metadata = $twig->render('metadata.xml', array(
    	'entityID' => $base . "metadata",	// convention: use metadata URL as entity ID
    	'Location' => $base . "sso",
        'X509Certificate' => $certdata,
    ));
    $response = new Response($metadata);
    $response->headers->set('Content-Type', 'text/xml');
    return $response;
});

# receive SAML request - assume HTTP-Redirect binding
$app->get('/sso', function (Request $request) use ($app) {
    $relay_state = $request->get('RelayState');
    $saml_request = $request->get('SAMLRequest');
    $saml_request = gzinflate(base64_decode($saml_request));
    $dom = new DOMDocument();
    $dom->loadXML($saml_request);
    $xpath = new DOMXPath($dom);
    $xpath->registerNamespace('samlp', "urn:oasis:names:tc:SAML:2.0:protocol" );
    $xpath->registerNamespace('saml', "urn:oasis:names:tc:SAML:2.0:assertion" );
    // ACS URL
    $query = "string(/samlp:AuthnRequest/@AssertionConsumerServiceURL)";
    $acs_url = $xpath->evaluate($query, $dom);
    if (!$acs_url) {
      throw new Exception('Could not locate AssertionConsumerServiceURL attribute.');
    }
    // TODO validate $acs_url

    // Request ID
    $query = "string(/samlp:AuthnRequest/@ID)";
    $requestID = $xpath->evaluate($query, $dom);
    // TODO validate $requestID

    // Audience
    $query = "string(/samlp:AuthnRequest/saml:Issuer)";
    $audience = $xpath->evaluate($query, $dom);
    if (!$audience) {
        throw new Exception('Could not locate Issuer element.');
    }
    // TODO validate $audience

    # send SAML response
    $base = $request->getUriForPath('/');
    $issuer = $base . 'metadata';	// convention
    # remote SP
    $destination = $acs_url; // TODO

    $dn = isset($_SERVER['SSL_CLIENT_S_DN']) ? $_SERVER['SSL_CLIENT_S_DN'] : "CN=test";

    $saml_response = samlResponse($issuer, $destination, $audience, $requestID, $dn);

    $cert = file_get_contents(CERTFILE);
    $key = file_get_contents(KEYFILE);
    if( $key ) {
        $dom = new DOMDocument();
        $dom->preserveWhiteSpace = FALSE;
        $dom->loadXML($saml_response);
        $dom->formatOutput = TRUE;
        $dom = utils_xml_sign($dom, $key, $cert);
        $saml_response = $dom->saveXML();
    }

    $server = parse_url($acs_url, PHP_URL_HOST);
    // TODO validate server

    $loader = new Twig_Loader_Filesystem('views');
    $twig = new Twig_Environment($loader, array(
        'debug' => true,
    ));

    $form = $twig->render('form.html', array(
        'action' => $acs_url,
        'server' => $server,
        'RelayState' => $relay_state,
        'Attributes' => $attributes,
        'SAMLResponse' => base64_encode($saml_response),
    ));
    return $form;
});

$app->run(); 
