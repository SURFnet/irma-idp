<?php
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;
use \Firebase\JWT\JWT;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

require __DIR__ . '/../vendor/autoload.php';

// NOTE that DEBUG is dangerous as unsanitised input may be rendered
define("DEBUG", false);
define("KEYFILE", "../key.pem");
define("CERTFILE", "../cert.pem");      // PEM encoded version
define("CERTFILE_DER", "../cert.crt"); // DER encoded version

define("NAMEIDFORMAT", "urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
define("AUTHNCONTEXTCLASSREF", "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified");

date_default_timezone_set('UTC');

$sps = [
    'https://surfdrive.surf.nl/' => [
        'acs' => 'todo',
        'map' => [
            'pbdf.surf.surfdrive.eppn' => 'urn:mace:dir:attribute-def:eduPersonPrincipalName',
            'pbdf.surf.surfdrive.emailadres' => 'urn:mace:dir:attribute-def:mail',
            'pbdf.surf.surfdrive.displayname' => 'urn:mace:dir:attribute-def:displayName',
        ],
        'add' => [ 
            'urn:mace:dir:attribute-def:eduPersonEntitlement' => 'urn:x-surfnet:surf.nl:surfdrive:quota:100',
            ]
        ],
        'IAMShowcase' => [
            'acs' => 'https://sptest.iamshowcase.com/acs',
            'map' => [
                'pbdf.surf.surfdrive.eppn' => 'PrincipalName',
                'pbdf.surf.surfdrive.emailadres' => 'mail',
                'pbdf.surf.surfdrive.displayname' => 'displayName',
            ],
            'add' => []
        ]
];

function samlResponse($issuer, $destination, $audience, $requestID, $nameid, $attributes) {
    global $twig;
    $id = "_"; for ($i = 0; $i < 42; $i++ ) $id .= dechex( rand(0,15) );
    $now = gmdate("Y-m-d\TH:i:s\Z", time());
    $notonorafter = gmdate("Y-m-d\TH:i:s\Z", time() + 60 * 5);
    $notbefore = gmdate("Y-m-d\TH:i:s\Z", time() - 30);

    return $twig->render('AuthnResponse.xml', array(
        'ID'                   => $id,
        'Issuer'               => $issuer,
        'IssueInstant'         => $now,
        'Destination'          => $destination,
        'Assertionid'          => 'TODO',
        'Audience'             => $audience,
        'InResponseTo'         => $requestID,
        'NotBefore'            => $notbefore,
        'NotOnOrAfter'         => $notonorafter,
        'NameIDFormat'         => NAMEIDFORMAT,
        'NameID'               => $nameid,
        'AuthnContextClassRef' => AUTHNCONTEXTCLASSREF,
        'attributes'           => $attributes,
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

function parseAuthnRequest($authn_request) {
    $request = gzinflate(base64_decode($authn_request));
    $dom = new DOMDocument();
    // make sure external entities are disabled
    $previous = libxml_disable_entity_loader(true);
    $dom->loadXML($request);
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

    // Request ID
    $query = "string(/samlp:AuthnRequest/@ID)";
    $requestID = $xpath->evaluate($query, $dom);
    if( FALSE === preg_match("/^[a-zA-Z_][0-9a-zA-Z._-]*$/", $requestID) )
        throw new Exception(sprintf("illegal ID '%s'", $requestID));

    // Issuer
    $query = "string(/samlp:AuthnRequest/saml:Issuer)";
    $issuer = $xpath->evaluate($query, $dom);
    if (!$issuer) {
        throw new Exception('Could not locate Issuer element.');
    }
    if( $issuer != filter_var($issuer, FILTER_SANITIZE_STRING)) // was: FILTER_VALIDATE_URL but some SPs violate the spec
        throw new Exception(sprintf("illegal issuer  '%s'", $issuer));

    return ["acs_url" => $acs_url, "requestID" => $requestID, "issuer" => $issuer];
}

$app = AppFactory::create();

$loader = new \Twig\Loader\FilesystemLoader('views');
$twig = new \Twig\Environment($loader, [
    // 'cache' => '/tmp',
]);

$config = [
    'sps' => $sps,
    'twig' => $twig,
];

$app->get('/', function (Request $request, Response $response, $args) {
    $url = $request->getUri()->withPath('metadata');
    $response->getBody()->write("This is a SAML IDP<br/>See also the SAML 2.0 <a href='$url'>Metadata</a>");
    return $response;
});

$app->get('/metadata', function (Request $request, Response $response, $args) use ($twig) {
    $der = file_get_contents(CERTFILE_DER);
    $metadata = $twig->render('metadata.xml', [
       'entityID' => $request->getUri()->withPath('metadata'), // convention: use metadata URL as entity ID
       'Location' => $request->getUri()->withPath('sso'),
       'X509Certificate' => $der ? base64_encode($der) : null,
    ]);
    $response->getBody()->write($metadata);
    return $response->withHeader('Content-type', 'text/xml');
});

# receive SAML request - assume HTTP-Redirect binding
$app->get('/sso', function (Request $request, Response $response, $args) use ($config) {
    $params = $request->getQueryParams();
    $relay_state = $params['RelayState']; // opaque string, handle with care, needs escaping
    $saml_request = $params['SAMLRequest'];
    if( $saml_request != filter_var( $saml_request, FILTER_VALIDATE_REGEXP, [ "options" => [ "regexp" => "/^[a-zA-Z0-9\/+_-]*={0,2}$/" ] ] ) )
        throw new Exception(sprintf("malformed SAMLRequest '%s'", $saml_request));
    $saml = parseAuthnRequest($saml_request);
    if( !array_key_exists( $saml['issuer'], $config['sps'] ) )
        throw new Exception(sprintf("Unknown SP '%s'", $saml['issuer'])); // issuer is a sanitized string/url
    if( !isset( $saml['acs_url'], $config['sps'][$saml['issuer']]['acs'] ) )
        throw new Exception(sprintf("Illegal ACS location '%s'", $saml['acs_url'])); // acs_url is a sanitized url

    $request = [
        "iat" => time(),
        "iss" => 'irma-idp',
        "sub" => "verification_request",
        "sprequest" => [
            "validity" => 60,
            "request" => [
                'type' => 'disclosing',
                'content' => [
                    [
                        'label' => 'eppn',
                        'attributes' => [ 'pbdf.surf.surfdrive.eppn' ],
                    ],
                    [
                        'label' => 'email',
                        'attributes' => [ 'pbdf.surf.surfdrive.emailadres' ],
                    ],
                    [
                        'label' => 'displayname',
                        'attributes' => [ 'pbdf.surf.surfdrive.displayname' ],
                    ],
                ]
            ]
        ]
    ];
    $pk = openssl_pkey_get_private("file://" . realpath('../jwt_key.pem'));
    $jwt = JWT::encode($request, $pk, "RS256", 'irma-idp');

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
    $session = file_get_contents($url, false, stream_context_create($post_opts)); // this is trusted external input
    error_log("IRMA session: " . $session);
    
    $disclosePage = $config['twig']->render('disclose.html', [
        'RelayState'  => $relay_state,
        'requestID'   => $saml['requestID'],
        'audience'    => $saml['issuer'],
        'session'     => $session,
    ]);
    $response->getBody()->write($disclosePage);
    return $response;
});

$app->post('/response', function (Request $request, Response $response, $args) use ($config) {
    $params = $request->getParsedBody();
    error_log( print_r($params, true) );

    $relay_state = $params['RelayState']; // opaque string, handle with care, needs escaping
    $requestID = $params['requestID'];
    if( FALSE === preg_match("/^[a-zA-Z_][0-9a-zA-Z._-]*$/", $requestID) )
        throw new Exception(sprintf("illegal ID '%s'", $requestID));
    $audience = $params['audience'];
    if( !array_key_exists( $audience, $config['sps'] ) )
        throw new Exception(sprintf("Unknown audience '%s'", $audience)); // audience must be tampered with
    $sp = $config['sps'][$audience];

    $token = $params['token'];
    if( $token != filter_var( $token, FILTER_VALIDATE_REGEXP, [ "options" => [ "regexp" => "/^[a-zA-Z0-9\/+_-]*={0,2}$/" ] ] ) )
        throw new Exception(sprintf("malformed token '%s'", $token));

    $result_jwt = file_get_contents("https://irmago.surfconext.nl/irmaserver/session/$token/result-jwt");
    $pubkeyfile = 'pubkey.pem';
    $pubkey = openssl_pkey_get_public("file://$pubkeyfile");
    $decoded = (array) JWT::decode($result_jwt, $pubkey, array('RS256'));
    error_log( print_r($decoded, true) );

    if( $decoded['proofStatus'] === 'VALID')
      error_log( json_encode($decoded['disclosed']) );

    $disclosed = $decoded['disclosed'];
    $attributes = [];
    foreach( $disclosed as $d) {
        $a = (array) $d;
        $attributes[$a["id"]] = $a["rawvalue"];
    }

    // map attributes
    $map = $sp['map'];
    $a = $sp['add'];
    foreach ($attributes as $key => $value) {
        if( array_key_exists($key, $map)) {
            $a[$map[$key]] = $value;
        } else {
            $a[$key] = $value;
        }
    }
    // hack
    if( $audience === 'https://surfdrive.surf.nl/' && array_key_exists('pbdf.surf.surfdrive.eppn', $attributes) ) {
        list($uid, $sho) = explode('@', $attributes['pbdf.surf.surfdrive.eppn']);
        if( isset($sho) ) $a['urn:mace:terena.org:attribute-def:schacHomeOrganization'] = $sho; // 'pilot.irma.surfdrive.nl'
        if( isset($uid) ) $a['urn:mace:dir:attribute-def:uid'] = $uid;
    }
    $attributes = $a;

    # send SAML response
    $issuer = $request->getUri()->withPath('metadata'); // convention: use metadata URL as entity ID
    # remote SP
    $destination = $sp['acs'];

    $nameid = "_"; for ($i = 0; $i < 20; $i++ ) $nameid .= dechex( rand(0,15) );
    error_log(">>>>>>>>>>>>>" . $nameid);
    $saml_response = samlResponse($issuer, $destination, $audience, $requestID, $nameid, $attributes);
    error_log($saml_response);

    $cert = file_get_contents(CERTFILE);
    $key = file_get_contents(KEYFILE);
    if( $key )
        $saml_response = sign($saml_response, $key, $cert);
        
    $x = $config['twig']->render('form.html', [
        'RelayState'   => $relay_state,
        'SAMLResponse' => base64_encode($saml_response),
        'action'       => $destination,
    ]);
    $response->getBody()->write($x);
    return $response;

});

$app->run();