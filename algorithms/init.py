"""
Cryptography Algorithms Package
Contains implementations of various encryption algorithms
"""

from .aes import AESAlgorithm
from .twofish import TwofishAlgorithm
from .des import DESAlgorithm
from .serpent import SerpentAlgorithm
from .rc4 import RC4Algorithm
from .caesar import CaesarAlgorithm
from .vigenere import VigenereAlgorithm
from .affine import AffineAlgorithm
from .playfair import PlayfairAlgorithm
from .hill import HillAlgorithm
from .rsa import RSAAlgorithm
from .dh import DHAlgorithm
from .ecc import ECCAlgorithm
from .elgamal import ElGamalAlgorithm
from .elgamal_signature import ElGamalSignatureAlgorithm
from .dsa_ecdsa import DSAAlgorithm, ECDSAAlgorithm, Ed25519Algorithm
from .rsa_signature import RSASignatureAlgorithm
from .md5 import MD5Algorithm
from .sha256 import SHA256Algorithm
from .sha512 import SHA512Algorithm
from .otp import OTPAlgorithm
from .rc6 import RC6Algorithm
from .mars import MARSAlgorithm

__all__ = [
    'AESAlgorithm',
    'TwofishAlgorithm',
    'DESAlgorithm',
    'SerpentAlgorithm',
    'RC4Algorithm',
    'CaesarAlgorithm',
    'VigenereAlgorithm',
    'AffineAlgorithm',
    'PlayfairAlgorithm',
    'HillAlgorithm',
    'RSAAlgorithm',
    'DHAlgorithm',
    'ECCAlgorithm',
    'ElGamalAlgorithm',
    'ElGamalSignatureAlgorithm',
    'DSAAlgorithm',
    'ECDSAAlgorithm',
    'Ed25519Algorithm',
    'RSASignatureAlgorithm',
    'MD5Algorithm',
    'SHA256Algorithm',
    'SHA512Algorithm',
    'OTPAlgorithm',
    'RC6Algorithm',
    'MARSAlgorithm'
]