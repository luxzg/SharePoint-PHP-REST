<?php

// create a token that works with SharePoint
// ver 0.5 - inner access/actor token works, but outer one still does not

// requires: jwt-php - to install
//      composer require firebase/php-jwt

// jwt-php's main file
//      /var/www/websitefolder/vendor/firebase/php-jwt/src/JWT.php

// if the library is the project, try to use the composer's autoload for the tests
$composerAutoload = __DIR__ . '/../vendor/autoload.php';

if (is_file($composerAutoload)) {
    include $composerAutoload;
} else {
    die('Unable to find autoload.php file, please use composer to load dependencies');
}

// namespace Firebase\JWT;

use \Firebase\JWT\JWT;

$privateKey = <<<EOD
-----BEGIN PRIVATE KEY-----
A....
<put your cert here>
.....Z
-----END PRIVATE KEY-----
EOD;

$publicKey = <<<EOD
-----BEGIN CERTIFICATE-----
B....
<put your cert here>
.....Y
-----END CERTIFICATE-----
EOD;

$current = time();
$expiration = time()+21600;
// echo "Current epoch time is: ".$current;
// echo "Expiration in 6 hours in epoch time is: ".$expiration;

// inner token also known as actor token, signed with private cert
$payloadin = array(
        "aud" => "00000003-0000-0ff1-ce00-000000000000/sharepoint.website.com@e89de187-11f3-464b-8677-6d60ec37e3ab",
        "iss" => "2985a155-3ae6-43b8-b535-7e011de69b36@e89de187-11f3-464b-8677-6d60ec37e3ab",
        "nbf" => $current,
        "exp" => $expiration,
        "nameid" => "0ed49099-108a-40a3-bb5e-03b4a60a1edc@e89de187-11f3-464b-8677-6d60ec37e3ab",
        "trustedfordelegation" => "true"
);

$keyId = null;

$headerin = array(
    "typ" => "JWT",
    "alg" => "RS256",
    "x5t" => "pRulVxZuOUrIH0ymgNzij2zq0po="
);

$jwtin = JWT::encode($payloadin, $privateKey, 'RS256', $keyId, $headerin);
echo "<pre>Encoded inner token (tested and works):\n" . print_r($jwtin, true) . "\n</pre>";



// stuff below does not work... get an error reply from sharepoint

// encoding function from php-jwt without signing; copied functions from jwt-php

function urlsafeB64Encode2($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

function jsonEncode2($input)
    {
        $json = json_encode($input);
        if ($errno = json_last_error()) {
            echo $errno;
        } elseif ($json === 'null' && $input !== null) {
            throw new DomainException('Null result with non-null input');
        }
        return $json;
    }

function encodewithoutsign($payload, $alg = 'none', $keyId = null, $head = null)
    {
        $header = array('typ' => 'JWT', 'alg' => $alg);
        if ($keyId !== null) {
            $header['kid'] = $keyId;
        }
        if (isset($head) && is_array($head)) {
            $header = array_merge($head, $header);
        }
        $segments = array();
        $segments[] = urlsafeB64Encode2(jsonEncode2($header));
        $segments[] = urlsafeB64Encode2(jsonEncode2($payload));

        return implode('.', $segments);
    }

// outer token, not signed, algorithm has to be 'none'
$payload = array(
    "aud" => '00000003-0000-0ff1-ce00-000000000000/sharepoint.website.com@e89de187-11f3-464b-8677-6d60ec37e3ab',
    "iss" => '2985a155-3ae6-43b8-b535-7e011de69b36@e89de187-11f3-464b-8677-6d60ec37e3ab',
    "nbf" => $current,
    "exp" => $expiration,
    "nameid" => 'S-1-5-21-0000000000-0000000000-0000000000-1111',
    "nii" => 'urn:office:idp:activedirectory',
    "actortoken" => $jwtin
);

// $keyId = null;

// $header = array(
//     "typ" => "JWT",
//     "alg" => "none"
// );

// no key!
// $jwt = encodewithoutsign($payload, 'none', $keyId, $header);

// keyId, header, and keys are not needed, made our own function by modifying one from JWT
$jwt = encodewithoutsign($payload);
echo "<pre>Encoded outer&inner tokens combined (does not work so far):\n" . print_r($jwt, true) . "\n</pre>";

echo "<br><br><br>";

$decoded = JWT::decode($jwt, 'none');

/*
 NOTE: This will now be an object instead of an associative array. To get
 an associative array, you will need to cast it as such:
*/

$decoded_array = (array) $decoded;
echo "<pre>Decode:\n" . print_r($decoded_array, true) . "\n</pre>";
?>
