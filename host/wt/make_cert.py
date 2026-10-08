#!/usr/bin/env python
"""Generate the self-signed certificate the local HTTP/3 relay presents.

WebTransport runs over QUIC, so the browser validates the certificate on its
own path and `--ignore-certificate-errors` is not enough to be confident about.
The reliable way is to pin the exact key: Chrome accepts
`--ignore-certificate-errors-spki-list=<base64 sha256 of the DER SPKI>`, which
this script prints.

The certificate lives under `.loop*/` because it is test scaffolding, not
source, and must never be reused for anything real.

Usage: python host/wt/make_cert.py [--dir .loop32] [--out spki.txt]
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def load_existing(cert_path: str, key_path: str):
    """Return an existing (cert, key) pair, or None if either is unusable.

    Regenerating on every run is actively harmful here: the browser trusts
    this certificate only because it was added to the Windows certificate
    store, so a fresh key each time invalidates that trust immediately and
    every subsequent run fails for a reason that looks like a code bug.
    """
    try:
        cert = x509.load_pem_x509_certificate(open(cert_path, "rb").read())
        key = serialization.load_pem_private_key(open(key_path, "rb").read(), password=None)
    except Exception:
        return None
    now = dt.datetime.now(dt.timezone.utc)
    if cert.not_valid_after_utc <= now + dt.timedelta(days=1):
        return None  # expired or about to be; make a new one
    return cert, key


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=".loop32")
    ap.add_argument("--out", default=".loop32/spki.txt")
    ap.add_argument(
        "--rotate",
        action="store_true",
        help="generate new keys even if they already exist (also requires "
        "re-adding the CA to the trust store)",
    )
    args = ap.parse_args()

    os.makedirs(args.dir, exist_ok=True)
    ca_cert_path = os.path.join(args.dir, "ca.pem")
    ca_key_path = os.path.join(args.dir, "ca-key.pem")
    cert_path = os.path.join(args.dir, "cert.pem")
    key_path = os.path.join(args.dir, "key.pem")

    if not args.rotate and load_existing(ca_cert_path, ca_key_path):
        ca_cert = x509.load_pem_x509_certificate(open(ca_cert_path, "rb").read())
        ca_key = serialization.load_pem_private_key(open(ca_key_path, "rb").read(), password=None)
        print("reusing existing CA")
    else:
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "openssh-moonbit-loop32 CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Loop #32 test only"),
            ]
        )
        now = dt.datetime.now(dt.timezone.utc)
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=30))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )
        write_pem(ca_cert_path, ca_cert.public_bytes(serialization.Encoding.PEM))
        write_pem(
            ca_key_path,
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )
        print("generated new CA")

    # The leaf is a normal server certificate with no CA capability. Presenting
    # a self-signed CA as the end-entity certificate is tolerated on the
    # classic TLS path but rejected on Chromium's QUIC path, so this is a real
    # two-level chain rather than a shortcut.
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]
    )
    san = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv6Address("::1")),
    ]
    now = dt.datetime.now(dt.timezone.utc)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    write_pem(cert_path, leaf.public_bytes(serialization.Encoding.PEM))
    write_pem(
        key_path,
        leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )
    # `chain.pem` is leaf-then-CA: the order a TLS server must present.
    write_pem(
        os.path.join(args.dir, "chain.pem"),
        leaf.public_bytes(serialization.Encoding.PEM)
        + ca_cert.public_bytes(serialization.Encoding.PEM),
    )

    # The browser may be told to trust the CA, or the leaf's key may be pinned.
    # Both are emitted: which one Chromium honours on the QUIC path is not
    # obvious, and guessing wrong looks exactly like a broken server.
    ca_spki = ca_cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    leaf_spki = leaf.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    ca_b64 = base64.b64encode(hashlib.sha256(ca_spki).digest()).decode()
    leaf_b64 = base64.b64encode(hashlib.sha256(leaf_spki).digest()).decode()
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(ca_b64 + "\n")
    with open(args.out.replace(".txt", "-leaf.txt"), "w", encoding="utf-8") as f:
        f.write(leaf_b64 + "\n")

    print(f"ca:      {ca_cert_path}")
    print(f"leaf:    {cert_path}")
    print(f"chain:   {os.path.join(args.dir, 'chain.pem')}")
    print(f"spki ca:   {ca_b64}")
    print(f"spki leaf: {leaf_b64}")
    print(f"install: certutil -user -f -addstore Root {ca_cert_path}")
    return 0


def write_pem(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows has no POSIX mode bits to set


if __name__ == "__main__":
    raise SystemExit(main())
