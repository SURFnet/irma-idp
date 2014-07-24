<?php
require_once __DIR__.'/../vendor/autoload.php';

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

function attributes() {
    $dn = $_SERVER['SSL_CLIENT_S_DN'];
    $attributes = array();
    foreach( explode('/',$dn) as $pair ) {
	if( $pair=='' ) continue;
	list($k, $v) = explode('=',$pair);
	$attributes[$k] = $v;
    }
    return $attributes;
}

function xpath( $query, $dom ) {
    $xpath = new DOMXPath($dom);
    $xpath->registerNamespace('samlp', "urn:oasis:names:tc:SAML:2.0:protocol" );
    return $xpath->evaluate($query, $dom);
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

########## SAML ##########

# SAML 2.0 Metadata

$app->get('/metadata', function (Request $request) use ($app) {
    $loader = new Twig_Loader_Filesystem('views');
    $twig = new Twig_Environment($loader, array(
    	'debug' => true,
    ));
    $base = $request->getUriForPath('/');
    $metadata = $twig->render('metadata.xml', array(
    	'entityID' => $base . "metadata",	// convention: use metadata URL as entity ID
    	'Location' => $base . "sso",
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
    $query = "string(/samlp:AuthnRequest/@AssertionConsumerServiceURL)";
    $acs_url = $xpath->evaluate($query, $dom);
    if (!$acs_url) {
      throw new Exception('Could not locate AssertionConsumerServiceURL attribute.');
    }
    $query = "string(/samlp:AuthnRequest/@ID)";
    $requestID = xpath($query, $dom);

    # send SAML response
    $base = $request->getUriForPath('/');
    $issuer = $base . 'metadata';	// convention
    # remote SP
    $destination = $acs_url; // TODO
    $now = gmdate("Y-m-d\TH:i:s\Z", time());
    $id = "_"; for ($i = 0; $i < 42; $i++ ) $id .= dechex( rand(0,15) );
    $notonorafter = gmdate("Y-m-d\TH:i:s\Z", time() + 60 * 5);
    $notbefore = gmdate("Y-m-d\TH:i:s\Z", time() - 30);

    $loader = new Twig_Loader_Filesystem('views');
    $twig = new Twig_Environment($loader, array(
    	'debug' => true,
    ));

    $saml_response = $twig->render('AuthnResponse.xml', array(
    	'ID' => $id,
    	'Issuer' => $issuer,
    	'IssueInstant' => $now,
    	'Destination' => $destination,
	'Assertionid'	=> 'TODO',
	'Audience'	=> 'TODO',
	'InResponseTo'	=> $requestID,
	'NotBefore'	=> $notbefore,
	'NotOnOrAfter'	=> $notbefore,
	'Subject'	=> $_SERVER['SSL_CLIENT_S_DN'],	// TODO nameidformat
	'attributes'	=> attributes(),
    ));

    # TODO: sign!

    $params = array();
    $params['action'] = $acs_url;
    $params['SAMLResponse'] = base64_encode($saml_response);
    if ($relay_state !== NULL) {
  	$params['RelayState'] = $relay_state; // TODO
    }
    $form = $twig->render('form.html', $params);
    return $form;
});

$app->run(); 
