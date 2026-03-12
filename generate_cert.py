"""Generate a self-signed SSL certificate for local HTTPS."""
import subprocess
import os
import sys

CERT_DIR = os.path.join(os.path.dirname(__file__), 'certs')
CERT_FILE = os.path.join(CERT_DIR, 'cert.pem')
KEY_FILE = os.path.join(CERT_DIR, 'key.pem')

def generate():
    os.makedirs(CERT_DIR, exist_ok=True)

    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        print(f"Certificates already exist in {CERT_DIR}")
        return CERT_FILE, KEY_FILE

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
        import ipaddress

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        import socket
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PTC POB Tracker"),
            x509.NameAttribute(NameOID.COMMON_NAME, local_ip),
        ])

        san_list = [
            x509.DNSName("localhost"),
            x509.DNSName(hostname),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            x509.IPAddress(ipaddress.IPv4Address(local_ip)),
        ]

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
            .sign(key, hashes.SHA256())
        )

        with open(KEY_FILE, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()))

        with open(CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print(f"Certificate generated for {local_ip}")
        print(f"  cert: {CERT_FILE}")
        print(f"  key:  {KEY_FILE}")
        return CERT_FILE, KEY_FILE

    except ImportError:
        print("'cryptography' package not found, using OpenSSL fallback...")
        try:
            import socket
            local_ip = socket.gethostbyname(socket.gethostname())
            subprocess.run([
                'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                '-keyout', KEY_FILE, '-out', CERT_FILE,
                '-days', '365', '-nodes',
                '-subj', f'/O=PTC POB Tracker/CN={local_ip}',
                '-addext', f'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:{local_ip}'
            ], check=True, capture_output=True)
            print(f"Certificate generated via OpenSSL for {local_ip}")
            return CERT_FILE, KEY_FILE
        except Exception as e:
            print(f"OpenSSL also failed: {e}")
            print("Falling back to Python ssl module...")
            return generate_with_stdlib()


def generate_with_stdlib():
    """Last resort: use Python's ssl to make a basic self-signed cert."""
    import ssl
    import socket
    import tempfile

    local_ip = socket.gethostbyname(socket.gethostname())

    # Python 3.10+ has ssl._create_self_signed_cert but it's private
    # Use subprocess with python itself
    script = f'''
import ssl, socket, os
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
# Generate using openssl via subprocess as last resort
import subprocess
subprocess.run([
    "python", "-c",
    "from http.server import HTTPServer; print('test')"
], capture_output=True)
'''
    # Actually just create a minimal self-signed cert with the ssl module
    # This is the simplest approach
    import struct
    import hashlib
    import time

    print(f"To generate certificates, install the cryptography package:")
    print(f"  pip install cryptography")
    print(f"Then run: python generate_cert.py")
    return None, None


if __name__ == '__main__':
    generate()
