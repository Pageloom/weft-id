<?php
/**
 * SAML 2.0 SP remote metadata.
 *
 * This file defines the Service Providers that can authenticate via this IdP.
 * For development, we trust the ACS URL from the SP's AuthnRequest.
 */

// Base SP configuration with explicit ACS URL
$sp_config = [
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    'simplesaml.nameidattribute' => 'email',
    'AssertionConsumerService' => [
        [
            'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            'Location' => 'https://dev.pageloom.localhost/saml/acs',
            'index' => 0,
        ],
    ],
];

// Dev SP - HTTP variant
$metadata['http://dev.pageloom.localhost/saml/metadata'] = $sp_config;

// Dev SP - HTTPS variant
$metadata['https://dev.pageloom.localhost/saml/metadata'] = $sp_config;
