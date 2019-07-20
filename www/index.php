<?php
require_once __DIR__.'/../vendor/autoload.php';

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use \Firebase\JWT\JWT;

// NOTE that DEBUG is dangerous as unsanitised input may be rendered
define("DEBUG", false);
define("KEYFILE", "../key.pem");
define("CERTFILE", "../cert.pem");      // PEM encoded version
define("CERTFILE_DER", "../cert.crt"); // DER encoded version

define("NAMEIDFORMAT", "urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
define("AUTHNCONTEXTCLASSREF", "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified");

date_default_timezone_set('UTC');

function samlResponse($issuer, $destination, $audience, $requestID, $nameid, $attributes) {
    $id = "_"; for ($i = 0; $i < 42; $i++ ) $id .= dechex( rand(0,15) );
    $now = gmdate("Y-m-d\TH:i:s\Z", time());
    $notonorafter = gmdate("Y-m-d\TH:i:s\Z", time() + 60 * 5);
    $notbefore = gmdate("Y-m-d\TH:i:s\Z", time() - 30);

    $loader = new Twig_Loader_Filesystem('views');
    $twig = new Twig_Environment($loader);

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
        'Subject'	=> $nameid,
        'AuthnContextClassRef' => AUTHNCONTEXTCLASSREF,
        'attributes'	=> $attributes,
    ));
}

function sign($response, $key, $cert) {
    $dom = new DOMDocument();
    $dom->preserveWhiteSpace = TRUE;
    $dom->loadXML($response);
    $dom->formatOutput = TRUE;
    $dsig = new XMLSecurityDSig();
    $dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
    $root = $dom->getElementsByTagName('Assertion')->item(0);
    assert('$root instanceof DOMElement');
    $insert_into = $dom->getElementsByTagName('Assertion')->item(0);
    $insert_before = $insert_into->getElementsByTagName('Subject')->item(0);
    $dsig->addReferenceList(array($root), XMLSecurityDSig::SHA256,
        array('http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N),
        array('id_name' => 'ID'));
    $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
    $objKey->loadKey($key);
    $dsig->sign($objKey);
    if ($cert)
        $dsig->add509Cert($cert, TRUE);
    $dsig->insertSignature($insert_into, $insert_before);
    return $dom->saveXML();
}

$app = new Silex\Application();
$app['debug'] = DEBUG;

$app->register(new Silex\Provider\SessionServiceProvider());
$app->register(new Silex\Provider\TwigServiceProvider(), array(
    'twig.path' => __DIR__.'/views',
));

$app->get('/', function (Request $request) use ($app) {
    $url = $request->getUriForPath('/') . 'metadata';
    return "This is a SAML IDP<br/>See also the SAML 2.0 <a href='$url'>Metadata</a>";
});

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
    $relay_state = $request->get('RelayState'); // TODO sanitize
    $saml_request = $request->get('SAMLRequest');

    $requestor = new \IRMA\Requestor("IRMA Identity Provider", "irma-idp", "../jwt_key.pem");
    $jwt = $requestor->getVerificationJwt([
	[
		"label" => "Over 18",
		"attributes" => [ "irma-demo.MijnOverheid.ageLower.over18" ]
	]
    ]);

    $post_opts = array('http' =>
      array(
        'method'  => 'POST',
        'content' => $jwt,
        'header'  => [
          "Content-Type: text/plain", # as required by irmago
        ]
      )
    );

    $url = 'https://irmago.surfconext.nl/irmaserver/session';
    $session = file_get_contents($url, false, stream_context_create($post_opts));
    return $app['twig']->render('disclose.html', [
        'RelayState'  => $relay_state,
        'SAMLRequest' => $saml_request,
        'session'     => $session,
    ]);
});

$app->post('/response', function (Request $request) use ($app) {
    $relay_state = $request->get('RelayState'); // TODO sanitize
    $saml_request = $request->get('SAMLRequest');
    $token = $request->get('token');

    $result_jwt = file_get_contents("https://irmago.surfconext.nl/irmaserver/session/$token/result-jwt");
    $pubkeyfile = 'pubkey.pem';
    $pubkey = openssl_pkey_get_public("file://$pubkeyfile");
    $decoded = (array) JWT::decode($result_jwt,$pubkey,array('RS256'));
    error_log( print_r($decoded,true) );

    if( $decoded['proofStatus'] === 'VALID')
      error_log( json_encode($decoded['disclosed']) );

    $disclosed = $decoded['disclosed'];
    $attributes = [];
    foreach( $disclosed as $d) {
        $a = (array) $d;
        $attributes[$a["id"]] = $a["rawvalue"];
    }
    $saml_request = gzinflate(base64_decode($saml_request));
    $dom = new DOMDocument();
    // make sure external entities are disabled
    $previous = libxml_disable_entity_loader(true);
    $dom->loadXML($saml_request);
    libxml_disable_entity_loader($previous);

    $xpath = new DOMXPath($dom);
    $xpath->registerNamespace('samlp', "urn:oasis:names:tc:SAML:2.0:protocol" );
    $xpath->registerNamespace('saml', "urn:oasis:names:tc:SAML:2.0:assertion" );
    // ACS URL
    $query = "string(/samlp:AuthnRequest/@AssertionConsumerServiceURL)";
    $acs_url = $xpath->evaluate($query, $dom);
    if (!$acs_url) {
      throw new Exception('Could not locate AssertionConsumerServiceURL attribute.');
    }

    if( $acs_url != filter_var($acs_url, FILTER_VALIDATE_URL))
        throw new Exception(sprintf("illegal ACS URL '%s'", $acs_url));
    $server = parse_url($acs_url, PHP_URL_HOST);

    // Request ID
    $query = "string(/samlp:AuthnRequest/@ID)";
    $requestID = $xpath->evaluate($query, $dom);
    if( FALSE === preg_match("/^[a-zA-Z_][0-9a-zA-Z._-]*$/", $requestID) )
        throw new Exception(sprintf("illegal ID '%s'", $requestID));

    // Audience
    $query = "string(/samlp:AuthnRequest/saml:Issuer)";
    $audience = $xpath->evaluate($query, $dom);
    if (!$audience) {
        throw new Exception('Could not locate Issuer element.');
    }
    if( $audience != filter_var($audience, FILTER_SANITIZE_STRING)) // was: FILTER_VALIDATE_URL but some SPs violate the spec
        throw new Exception(sprintf("illegal issuer  '%s'", $audience));

    # send SAML response
    $base = $request->getUriForPath('/');
    $issuer = $base . 'metadata';	// convention
    # remote SP
    $destination = $acs_url;

    $nameid = "_"; for ($i = 0; $i < 20; $i++ ) $nameid .= dechex( rand(0,15) );
    $saml_response = samlResponse($issuer, $destination, $audience, $requestID, $nameid, $attributes);

    $cert = file_get_contents(CERTFILE);
    $key = file_get_contents(KEYFILE);
    if( $key )
        $saml_response = sign($saml_response, $key, $cert);

    return $app['twig']->render('form.html', array(
        'action' => $acs_url,
        'server' => $server,
        'RelayState' => $relay_state,
        'Attributes' => $attributes,
        'SAMLResponse' => base64_encode($saml_response),
    ));
});

$app->run();
