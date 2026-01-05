<?php
/**
 * SimpleSAMLphp authentication sources configuration.
 *
 * This file defines test users for the local SAML IdP simulator.
 * DO NOT use these credentials in production.
 */

$config = [
    // Admin authentication for SimpleSAMLphp admin interface
    'admin' => [
        'core:AdminPassword',
    ],

    // Example authentication source with test users
    'example-userpass' => [
        'exampleauth:UserPass',

        // Test Super Admin user
        'admin@example.com:password123' => [
            'uid' => ['admin'],
            'email' => ['admin@example.com'],
            'firstName' => ['Admin'],
            'lastName' => ['User'],
            'displayName' => ['Admin User'],
            'groups' => ['admins', 'users'],
        ],

        // Test regular user
        'user@example.com:password123' => [
            'uid' => ['user'],
            'email' => ['user@example.com'],
            'firstName' => ['Test'],
            'lastName' => ['User'],
            'displayName' => ['Test User'],
            'groups' => ['users'],
        ],

        // Test user with different domain
        'alice@acme.com:password123' => [
            'uid' => ['alice'],
            'email' => ['alice@acme.com'],
            'firstName' => ['Alice'],
            'lastName' => ['Smith'],
            'displayName' => ['Alice Smith'],
            'groups' => ['users'],
        ],

        // Test user for JIT provisioning testing
        'newuser@example.com:password123' => [
            'uid' => ['newuser'],
            'email' => ['newuser@example.com'],
            'firstName' => ['New'],
            'lastName' => ['User'],
            'displayName' => ['New User'],
            'groups' => ['users'],
        ],
    ],
];
