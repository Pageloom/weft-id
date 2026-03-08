# Signing Certificates

Each service provider gets its own X.509 signing certificate. WeftId uses this certificate to sign the SAML assertions it sends to the application.

## How it works

When you register a service provider, WeftId automatically generates a signing certificate. The certificate's public key is included in the IdP metadata URL, so the application can verify assertion signatures.

The certificate validity period is controlled by the tenant-wide [certificate settings](../security/certificates.md).

## Viewing the certificate

The SP's **Certificates** tab shows the current signing certificate, including its expiration date and PEM-encoded public certificate.

## Rotation

When a certificate approaches expiry (based on the configured [rotation window](../security/certificates.md)), you can rotate it:

1. Go to the SP's **Certificates** tab
2. Click **Rotate Certificate**
3. Set a grace period (default: 7 days)

During the grace period, both the old and new certificates are valid. This gives the application time to update its trust configuration with the new certificate. After the grace period ends, only the new certificate is valid.

## Metadata refresh after rotation

After rotating a certificate, the application needs to pick up the new certificate. If the application imports WeftId's metadata by URL, it will get the new certificate automatically on its next metadata refresh.
