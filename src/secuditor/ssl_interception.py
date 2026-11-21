# Secuditor CLI – Copyright (c) 2026 Menahem Levinski

"""Cross-platform SSL/TLS interception and certificate trust inspection."""

import json
import re
import socket
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

try:
    import certifi
except ImportError:
    certifi = None

__all__ = ["SSLInterception", "SSLInterceptionAudit", "SSLInspection"]

LEGIT_ISSUERS = (
    "Kaspersky",
    "Fortinet",
    "Zscaler",
    "Blue Coat",
    "Symantec",
    "Cisco Umbrella",
    "Cisco Firepower",
    "Sophos",
    "ESET",
    "McAfee",
    "Bitdefender",
    "Check Point",
    "Palo Alto Networks",
    "Trend Micro",
    "Forcepoint",
    "Barracuda",
    "F5 Networks",
    "Juniper Networks",
    "CrowdStrike",
    "AVG Technologies",
    "AVG Antivirus",
    "AVG Web Shield",
    "Avast",
    "IBM Security",
    "Netskope",
    "Websense",
    "McAfee Network Security",
    "Cloudflare Gateway",
    "Forcepoint Web Security",
    "Symantec Web Security",
    "Trellix",
    "WatchGuard",
    "SonicWall",
    "Sangfor",
    "Securly",
    "Menlo Security",
    "iboss",
    "Cato Networks",
    "SentinelOne",
    "Broadcom",
    "Global Secure Access",
    "Microsoft Defender",
    "Perimeter 81",
    "Akamai",
    "Proofpoint",
    "Skyhigh Security",
)

PUBLIC_CAS = (
    "DigiCert",
    "Let's Encrypt",
    "GlobalSign",
    "Entrust",
    "Sectigo",
    "GoDaddy",
    "Google Trust Services",
    "Microsoft RSA TLS CA",
    "Microsoft Azure TLS Issuing CA",
    "Cloudflare Inc ECC CA",
    "Cloudflare Inc RSA CA",
    "Atos",
    "Apple",
    "Amazon",
    "Internet Security Research Group",
    "Cloudflare",
    "Starfield",
    "Comodo",
    "Izenpe",
    "QuoVadis",
    "UserTrust",
    "Buypass",
    "SwissSign",
    "Trustwave",
    "Amazon Trust Services",
    "GeoTrust",
    "IdenTrust",
    "Certum",
    "ZeroSSL",
    "Secom",
    "AC Camerfirma",
    "T-Systems",
    "SSL.com",
    "TrustAsia",
    "HARICA",
    "Actalis",
    "ACCV",
    "ISRG",
    "AC Raíz Certicámara",
    "E-Tugra",
    "Certigna",
    "XRamp",
    "OISTE",
    "CFCA",
    "Telia",
    "eMudhra",
    "D-TRUST",
    "ANF Autoridad de Certificación",
    "ANF AC",
)


class SSLInterceptionAudit:
    """Inspect TLS certificates to detect transparent SSL/TLS interception."""

    def __init__(self, host="www.google.com", port=443, timeout=5.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    @staticmethod
    def _host_matches_pattern(host: str, pattern: str) -> bool:
        """Match a hostname against a certificate CN/SAN pattern including wildcards."""
        h = (host or "").strip().lower().rstrip(".")
        p = (pattern or "").strip().lower().rstrip(".")
        if not h or not p:
            return False
        if h == p:
            return True
        if p.startswith("*."):
            base = p[2:]
            if (
                base
                and h.endswith("." + base)
                and h.count(".") == base.count(".") + 1
            ):
                return True
        return False

    @staticmethod
    def _extract_issuer_fields(cert) -> list[str]:
        """Extract O, CN, and OU attribute values from a certificate issuer."""
        fields = []
        for oid in (
            NameOID.ORGANIZATION_NAME,
            NameOID.COMMON_NAME,
            NameOID.ORGANIZATIONAL_UNIT_NAME,
        ):
            try:
                for attr in cert.issuer.get_attributes_for_oid(oid):
                    val = str(attr.value or "").strip()
                    if val:
                        fields.append(val)
            except Exception:
                continue
        return fields

    @staticmethod
    def _matches_issuer_list(fields: list[str], candidates) -> str | None:
        """Match any candidate CA/vendor against issuer RDN values using token boundaries."""
        for token in candidates or ():
            tok = str(token or "").strip()
            if not tok:
                continue
            pattern = re.compile(
                rf"(?<!\w){re.escape(tok)}(?!\w)", re.IGNORECASE
            )
            for field in fields:
                if pattern.search(field):
                    return tok
        return None

    def _fetch_peer_cert(self, host: str, port: int, context: ssl.SSLContext):
        """Connect, perform TLS handshake, and return (DER bytes, negotiated TLS version)."""
        with socket.create_connection((host, port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.getpeercert(binary_form=True), ssock.version()

    def _verify_public_chain(self, host: str, port: int) -> bool | None:
        """Verify certificate chain against public WebPKI roots (certifi)."""
        if certifi is None:
            return None
        try:
            public_ctx = ssl.create_default_context(cafile=certifi.where())
            public_ctx.check_hostname = True
            public_ctx.verify_mode = ssl.CERT_REQUIRED
            self._fetch_peer_cert(host, port, public_ctx)
            return True
        except ssl.SSLCertVerificationError:
            return False
        except Exception:
            return None

    def check_ssl_inspection(self, host=None, port=None):
        """Perform the 2-stage TLS certificate inspection against host:port."""
        target_host = str(host if host is not None else self.host).strip()
        target_port = int(port if port is not None else self.port)

        try:
            if not target_host or any(ord(ch) < 32 for ch in target_host):
                raise ValueError("Invalid target host")
            if not (1 <= target_port <= 65535):
                raise ValueError("Invalid target port")

            # Stage 1: Verify against the OS certificate trust store.
            os_ctx = ssl.create_default_context()
            os_ctx.check_hostname = True
            os_ctx.verify_mode = ssl.CERT_REQUIRED

            os_trusted = True
            verify_error = None
            try:
                der, tls_version = self._fetch_peer_cert(
                    target_host, target_port, os_ctx
                )
            except ssl.SSLCertVerificationError as verify_exc:
                os_trusted = False
                verify_error = (
                    getattr(verify_exc, "verify_message", None)
                    or str(verify_exc)
                )
                # Fallback unverified fetch only to extract certificate metadata for reporting.
                raw_ctx = ssl.create_default_context()
                raw_ctx.check_hostname = False
                raw_ctx.verify_mode = ssl.CERT_NONE
                der, tls_version = self._fetch_peer_cert(
                    target_host, target_port, raw_ctx
                )

            # Stage 2: Check whether an OS-trusted cert also chains to a public WebPKI root.
            public_trusted = (
                self._verify_public_chain(target_host, target_port)
                if os_trusted
                else False
            )

            cert = x509.load_der_x509_certificate(der)
            issuer = cert.issuer.rfc4514_string()
            subject = cert.subject.rfc4514_string()
            cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            common_name = cn_attrs[0].value if cn_attrs else ""

            try:
                san = cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                san = []

            not_before = getattr(
                cert, "not_valid_before_utc", None
            ) or cert.not_valid_before
            not_after = getattr(
                cert, "not_valid_after_utc", None
            ) or cert.not_valid_after

            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            sig_hash_algo = cert.signature_hash_algorithm
            if sig_hash_algo is not None:
                sig_algo = sig_hash_algo.name.lower()
            else:
                sig_algo = cert.signature_algorithm_oid._name.lower()

            key_type = "Unknown"
            key_bits = None
            key_strength = "Unknown"

            try:
                public_key = cert.public_key()

                if isinstance(public_key, rsa.RSAPublicKey):
                    key_type = "RSA"
                    key_bits = public_key.key_size
                    if key_bits < 2048:
                        key_strength = "Weak"
                    elif key_bits < 4096:
                        key_strength = "Moderate"
                    else:
                        key_strength = "Strong"

                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    key_type = "ECC"
                    key_bits = public_key.key_size
                    if key_bits < 256:
                        key_strength = "Weak"
                    elif key_bits < 384:
                        key_strength = "Moderate"
                    else:
                        key_strength = "Strong"

                elif isinstance(public_key, ed25519.Ed25519PublicKey):
                    key_type = "Ed25519"
                    key_bits = 256
                    key_strength = "Strong"

                elif isinstance(public_key, ed448.Ed448PublicKey):
                    key_type = "Ed448"
                    key_bits = 456
                    key_strength = "Strong"

                else:
                    key_type = type(public_key).__name__

            except Exception:
                pass

            # Detection & classification.
            issuer_fields = self._extract_issuer_fields(cert)
            matched_public_ca = self._matches_issuer_list(
                issuer_fields, PUBLIC_CAS
            )
            matched_legit_vendor = self._matches_issuer_list(
                issuer_fields, LEGIT_ISSUERS
            )

            triggers = []
            trust_mismatch = False

            if not os_trusted:
                trust_mismatch = True
                triggers.append(
                    f"Untrusted certificate ({verify_error})"
                    if verify_error
                    else "Untrusted certificate"
                )
            elif public_trusted is False:
                trust_mismatch = True
                triggers.append("Non-public root CA")
            elif public_trusted is None and not matched_public_ca:
                trust_mismatch = True
                triggers.append("Unknown issuer")

            validity_days = (not_after - not_before).days
            unusual_lifetime = validity_days <= 0 or validity_days > 825
            if unusual_lifetime:
                triggers.append("Unusual certificate lifetime")

            if san:
                host_matched = any(
                    self._host_matches_pattern(target_host, s) for s in san
                )
            else:
                host_matched = bool(common_name) and self._host_matches_pattern(
                    target_host, common_name
                )
            if not host_matched:
                triggers.append("CN/SAN mismatch")

            weak_sig = sig_algo in ("md5", "sha1")
            if weak_sig:
                triggers.append("Weak signature algorithm")

            inspected = trust_mismatch or (not host_matched)
            legit = False
            reason = None

            if inspected:
                if (
                    not os_trusted
                    or not host_matched
                    or weak_sig
                    or unusual_lifetime
                ):
                    verdict = "Suspicious"
                    reason = ", ".join(triggers)
                elif matched_legit_vendor:
                    legit = True
                    verdict = "Likely Legitimate"
                    reason = (
                        f"Issued by {matched_legit_vendor} (firewall inspection)"
                    )
                else:
                    verdict = "Suspicious"
                    reason = ", ".join(triggers)
            elif triggers:
                verdict = "Suspicious"
                reason = ", ".join(triggers)
            else:
                verdict = "Not Detected"

            return {
                "host": target_host,
                "subject": subject,
                "issuer": issuer,
                "common_name": common_name or "N/A",
                "san": san,
                "valid_from": not_before.isoformat(),
                "valid_to": not_after.isoformat(),
                "fingerprint_sha256": fingerprint,
                "signature_algo": sig_algo,
                "tls_version": tls_version,
                "key_type": key_type,
                "key_bits": key_bits,
                "key_strength": key_strength,
                "ssl_interception_detected": inspected,
                "interception_legit": legit,
                "interception_reason": reason,
                "verdict": verdict,
            }

        except Exception as exc:
            return {
                "host": target_host,
                "error": str(exc),
                "ssl_interception_detected": False,
                "interception_legit": False,
                "interception_reason": str(exc),
                "verdict": "Unknown",
            }

    def audit(self, host=None, port=None):
        """Run the SSL interception audit and return a structured report."""
        return self.check_ssl_inspection(host=host, port=port)


SSLInterception = SSLInterceptionAudit
SSLInspection = SSLInterceptionAudit

if __name__ == "__main__":
    print(json.dumps(
        SSLInterceptionAudit().audit(),
        indent=2,
        ensure_ascii=False,
    ))
