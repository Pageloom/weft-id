<?php
/**
 * SAML 2.0 IdP hosted metadata configuration.
 *
 * This configures SimpleSAMLphp as a SAML 2.0 Identity Provider.
 */

$metadata['__DYNAMIC:1__'] = [
    // The hostname for this IdP. This makes it work at any host.
    'host' => '__DEFAULT__',

    // The private key and certificate used for signing
    'privatekey' => 'idp.pem',
    'certificate' => 'idp.crt',

    // The authentication source to use
    'auth' => 'example-userpass',

    // Send attributes with simple names (email, firstName, lastName)
    // No authproc mapping - keeps attribute names as-is from authsources.php

    // NameID format - use email address
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',

    // Use email attribute as NameID
    'simplesaml.nameidattribute' => 'email',
];
