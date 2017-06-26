"""Certbot client crypto utility functions.

.. todo:: Make the transition to use PSS rather than PKCS1_v1_5 when the server
    is capable of handling the signatures.

"""
import hashlib
import logging
import os
import re

import OpenSSL
import pyrfc3339
import six

from cryptography.hazmat.backends import default_backend
from cryptography import x509


logging.basicConfig()
logger = logging.getLogger(__name__)


def validate_privkey(privkey_data):
    try:
        return OpenSSL.crypto.load_privatekey(
            OpenSSL.crypto.FILETYPE_PEM, privkey_data).check()
    except (TypeError, OpenSSL.crypto.Error) as error:
        logger.exception(error)
        return False


def validate_cert(privkey_data, cert_data, ca_cert_data):
    # For checking that your certs were not corrupted on disk.
    # 
    # Several things are checked:
    #     1. Check that the private key matches the certificate.
    #     2. Signature verification for the cert.
    #
    _validate_cert_matches_priv_key(privkey_data, cert_data)
    _validate_cert_sig(cert_data, ca_cert_data)


def _validate_cert_sig(cert_data, ca_cert_data):
    # Verifies the signature of a cert
    try:
        chain, _ = _pyopenssl_load_certificate(ca_cert_data)
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        hash_name = cert.signature_hash_algorithm.name
        OpenSSL.crypto.verify(chain, cert.signature, cert.tbs_certificate_bytes, hash_name)
    except (IOError, ValueError, OpenSSL.crypto.Error) as e:
        error_str = "verifying the signature of the cert has failed. \
                Details: {0}".format(e)
        logger.exception(error_str)
        raise Exception(error_str)


def _validate_cert_matches_priv_key(key_data, cert_data):
    # Verifies that the private key and cert match.
    try:
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_data)
        privkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_data)
        context = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
        context.use_privatekey(privkey)
        context.use_certificate(cert)
        context.check_privatekey()
    except (IOError, OpenSSL.SSL.Error) as e:
        error_str = "verifying the cert matches the private key has failed. \
                Details: {0}".format(e)
        logger.exception(error_str)
        raise Exception(error_str)


def _pyopenssl_load_certificate(data):
    openssl_errors = []
    for file_type in (OpenSSL.crypto.FILETYPE_PEM, OpenSSL.crypto.FILETYPE_ASN1):
        try:
            return OpenSSL.crypto.load_certificate(file_type, data), file_type
        except OpenSSL.crypto.Error as error:  # TODO: other errors?
            openssl_errors.append(error)
    raise Exception("Unable to load: {0}".format(",".join(
        str(error) for error in openssl_errors)))


def _load_cert(cert_data, load_func, typ=OpenSSL.crypto.FILETYPE_PEM):
    try:
        return load_func(typ, cert_data)
    except OpenSSL.crypto.Error as error:
        logger.exception(error)
        raise

def _pyopenssl_cert_san(cert_data):
    """Get Subject Alternative Names from certificate or CSR using pyOpenSSL.

    .. todo:: Implement directly in PyOpenSSL!

    .. note:: Although this is `acme` internal API, it is used by
        `letsencrypt`.

    :param cert_or_req: Certificate or CSR.
    :type cert_or_req: `OpenSSL.crypto.X509` or `OpenSSL.crypto.X509Req`.

    :returns: A list of Subject Alternative Names.
    :rtype: `list` of `unicode`

    """
    # This function finds SANs by dumping the certificate/CSR to text and
    # searching for "X509v3 Subject Alternative Name" in the text. This method
    # is used to support PyOpenSSL version 0.13 where the
    # `_subjectAltNameString` and `get_extensions` methods are not available
    # for CSRs.

    # constants based on PyOpenSSL certificate/CSR text dump
    part_separator = ":"
    parts_separator = ", "
    prefix = "DNS" + part_separator

    if isinstance(cert_data, OpenSSL.crypto.X509):
        func = OpenSSL.crypto.dump_certificate
    else:
        func = OpenSSL.crypto.dump_certificate_request
    text = func(OpenSSL.crypto.FILETYPE_TEXT, cert_data).decode("utf-8")
    # WARNING: this function does not support multiple SANs extensions.
    # Multiple X509v3 extensions of the same type is disallowed by RFC 5280.
    match = re.search(r"X509v3 Subject Alternative Name:\s*(.*)", text)
    # WARNING: this function assumes that no SAN can include
    # parts_separator, hence the split!
    sans_parts = [] if match is None else match.group(1).split(parts_separator)

    return [part.split(part_separator)[1]
            for part in sans_parts if part.startswith(prefix)]


def get_cn_from_cert(cert_data, typ=OpenSSL.crypto.FILETYPE_PEM):
    loaded_cert = _load_cert(cert_data, OpenSSL.crypto.load_certificate, typ)
    return loaded_cert.get_subject().CN


def get_sans_from_cert(cert_data, typ=OpenSSL.crypto.FILETYPE_PEM):
    return _pyopenssl_cert_san(
        _load_cert(cert_data, OpenSSL.crypto.load_certificate, typ))


def get_names_from_cert(cert_data, typ=OpenSSL.crypto.FILETYPE_PEM):
    loaded_cert = _load_cert(cert_data, OpenSSL.crypto.load_certificate, typ)
    common_name = loaded_cert.get_subject().CN
    sans = _pyopenssl_cert_san(loaded_cert)

    if common_name is None:
        return sans
    else:
        return [common_name] + [d for d in sans if d != common_name]


def get_not_before(cert_data):
    return _not_after_before(cert_data, OpenSSL.crypto.X509.get_notBefore)


def get_not_after(cert_data):
    return _not_after_before(cert_data, OpenSSL.crypto.X509.get_notAfter)


def _not_after_before(cert_data, method):
    """Internal helper function for finding notbefore/notafter.

    :param str cert_path: path to a cert in PEM format
    :param function method: one of ``OpenSSL.crypto.X509.get_notBefore``
        or ``OpenSSL.crypto.X509.get_notAfter``

    :returns: the notBefore or notAfter value from the cert at cert_path
    :rtype: :class:`datetime.datetime`

    """
    # pylint: disable=redefined-outer-name
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_data)
    # pyopenssl always returns bytes
    timestamp = method(x509)
    reformatted_timestamp = [timestamp[0:4], b"-", timestamp[4:6], b"-",
                             timestamp[6:8], b"T", timestamp[8:10], b":",
                             timestamp[10:12], b":", timestamp[12:]]
    timestamp_str = b"".join(reformatted_timestamp)
    print timestamp_str
    # pyrfc3339 uses "native" strings. That is, bytes on Python 2 and unicode
    # on Python 3
    if six.PY3:
        timestamp_str = timestamp_str.decode('ascii')
    return pyrfc3339.parse(timestamp_str)
