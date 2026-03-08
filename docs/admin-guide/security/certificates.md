# Certificates

Configure how long newly generated certificates remain valid and when rotation begins.

Navigate to **Settings > Security > Certificates**.

## Validity period

How long newly generated certificates remain valid. This applies to all certificate types: SP signing certificates and IdP connection certificates. Changing this setting does not affect existing certificates.

* 1 year
* 2 years
* 3 years
* 5 years
* 10 years (default)

## Rotation window

How far before expiry a new certificate is generated. During this window, both old and new certificates are valid so downstream services can update their trust configuration.

* 14 days
* 30 days
* 60 days
* 90 days (default)
