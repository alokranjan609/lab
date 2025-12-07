from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from datetime import datetime, timedelta


def create_rsa_key_pair():
    """Generate RSA private + public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def create_self_signed_certificate(private_key, public_key):
    """Create a self-signed X.509 certificate using the given key pair."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Bihar"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Patna"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Example Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"example.com"),
    ])

    # Validity period: from now to now + 30 days
    not_before = datetime.utcnow()
    not_after = not_before + timedelta(days=30)

    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)          # self-signed → issuer = subject
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
    )

    # Sign the certificate using the private key (RSA + SHA-256)
    certificate = cert_builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    return certificate


def print_keys_and_cert(private_key, public_key, certificate):
    """Print PEM encoded private key, public key, and certificate."""
    # Private key in PEM format
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # PKCS#1
        encryption_algorithm=serialization.NoEncryption()
    )

    # Public key in PEM format
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Certificate in PEM format
    cert_pem = certificate.public_bytes(
        encoding=serialization.Encoding.PEM
    )

    print("=== PRIVATE KEY (PEM) ===")
    print(priv_pem.decode())
    print("=== PUBLIC KEY (PEM) ===")
    print(pub_pem.decode())
    print("=== SELF-SIGNED CERTIFICATE (PEM) ===")
    print(cert_pem.decode())

    # Show validity period clearly
    print("=== CERTIFICATE VALIDITY PERIOD ===")
    print("Not Before :", certificate.not_valid_before)
    print("Not After  :", certificate.not_valid_after)


def verify_certificate_signature(certificate):
    """Verify that the certificate is signed by its own public key (self-signed)."""
    public_key = certificate.public_key()
    try:
        public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm
        )
        print("Certificate signature verification: SUCCESS")
    except Exception as e:
        print("Certificate signature verification: FAILED")
        print("Reason:", e)


def check_certificate_validity_period(certificate):
    """Check if the current time is within the certificate's validity period."""
    now = datetime.utcnow()
    print("\n=== VALIDITY CHECK ===")
    print("Current time (UTC):", now)
    print("Not Before         :", certificate.not_valid_before)
    print("Not After          :", certificate.not_valid_after)

    if certificate.not_valid_before <= now <= certificate.not_valid_after:
        print("Certificate is currently VALID (within validity period).")
    else:
        print("Certificate is NOT VALID (outside validity period).")


def main():
    print("=== Self-Signed Certificate using RSA Key Pair ===\n")

    # 1. Generate RSA key pair
    private_key, public_key = create_rsa_key_pair()
    print("RSA key pair generated.")

    # 2. Create self-signed certificate
    certificate = create_self_signed_certificate(private_key, public_key)
    print("Self-signed certificate created.\n")

    # 3. Print keys and certificate (PEM format) and validity
    print_keys_and_cert(private_key, public_key, certificate)

    # 4. Verify certificate signature
    print("\n=== SIGNATURE VERIFICATION ===")
    verify_certificate_signature(certificate)

    # 5. Check validity period
    check_certificate_validity_period(certificate)


if __name__ == "__main__":
    main()
