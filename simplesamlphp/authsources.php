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
        'admin-dev@pageloom.com:password123' => [
            'uid' => ['admin'],
            'email' => ['admin-dev@pageloom.com'],
            'firstName' => ['Admin'],
            'lastName' => ['User'],
            'displayName' => ['Admin User'],
            'groups' => ['admins', 'users'],
        ],

        // Test regular user
        'member-dev@pageloom.com:password123' => [
            'uid' => ['user'],
            'email' => ['member-dev@pageloom.com'],
            'firstName' => ['Member'],
            'lastName' => ['Normal'],
            'displayName' => ['Normal Member'],
            'groups' => ['users'],
        ],

        // Test Super Admin user
        'super-dev@pageloom.com:password123' => [
            'uid' => ['super'],
            'email' => ['super-dev@pageloom.com'],
            'firstName' => ['Super'],
            'lastName' => ['Admin'],
            'displayName' => ['Super Admin'],
            'groups' => ['admins', 'users'],
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
