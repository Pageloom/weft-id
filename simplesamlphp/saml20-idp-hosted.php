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

    // Attributes to include in assertions
    'attributes.NameFormat' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',

    // Map internal attribute names to SAML attribute names
    'authproc' => [
        // Convert attribute names to standard format
        100 => [
            'class' => 'core:AttributeMap',
            'email' => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
            'firstName' => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
            'lastName' => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
            'displayName' => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
        ],
    ],

    // NameID format - use email address
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',

    // Use email attribute as NameID
    'simplesaml.nameidattribute' => 'email',
];
