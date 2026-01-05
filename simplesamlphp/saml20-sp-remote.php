<?php
/**
 * SAML 2.0 SP remote metadata.
 *
 * This file defines the Service Providers that can authenticate via this IdP.
 * For development, we trust the ACS URL from the SP's AuthnRequest.
 */

// Base SP configuration
// By NOT specifying AssertionConsumerService, SimpleSAMLphp will use
// the AssertionConsumerServiceURL from the AuthnRequest
$sp_config = [
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    'simplesaml.nameidattribute' => 'email',
];

// Dev SP - HTTP variant
$metadata['http://dev.pageloom.localhost/saml/metadata'] = $sp_config;

// Dev SP - HTTPS variant
$metadata['https://dev.pageloom.localhost/saml/metadata'] = $sp_config;
