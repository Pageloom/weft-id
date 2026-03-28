"""XLSX encryption utility using msoffcrypto-tool.

Encrypts and decrypts openpyxl Workbooks with AES encryption
compatible with Excel, LibreOffice, and Google Sheets.
"""

import logging
from io import BytesIO
from typing import NamedTuple

from utils.wordlist import generate_passphrase

logger = logging.getLogger(__name__)


class EncryptedWorkbook(NamedTuple):
    """Result of encrypting a workbook."""

    data: BytesIO
    password: str
    file_size: int


def encrypt_workbook(workbook) -> EncryptedWorkbook:  # type: ignore[type-arg]
    """Encrypt an openpyxl Workbook with a generated passphrase.

    The workbook is saved to an in-memory buffer, encrypted using
    msoffcrypto-tool (AES), and returned with the generated password.
    The plaintext workbook is never written to storage.

    Args:
        workbook: An openpyxl Workbook instance

    Returns:
        EncryptedWorkbook with encrypted data buffer, password, and file size
    """
    from msoffcrypto.format.ooxml import OOXMLFile

    # Save workbook to plaintext buffer (in-memory only)
    plaintext_buffer = BytesIO()
    workbook.save(plaintext_buffer)
    plaintext_buffer.seek(0)

    # Generate passphrase
    password = generate_passphrase()

    # Encrypt
    encrypted_buffer = BytesIO()
    file = OOXMLFile(plaintext_buffer)
    file.encrypt(password, encrypted_buffer)
    encrypted_buffer.seek(0)

    file_size = encrypted_buffer.getbuffer().nbytes

    logger.info("Encrypted XLSX workbook (%d bytes)", file_size)

    return EncryptedWorkbook(
        data=encrypted_buffer,
        password=password,
        file_size=file_size,
    )


def decrypt_xlsx_data(file_data: bytes, password: str) -> bytes:
    """Decrypt an encrypted XLSX file using the given password.

    Args:
        file_data: Raw bytes of the encrypted XLSX file
        password: The passphrase used to encrypt the file

    Returns:
        Decrypted XLSX file bytes

    Raises:
        ValueError: If the file cannot be decrypted (wrong password or not encrypted)
    """
    import msoffcrypto

    try:
        encrypted_buffer = BytesIO(file_data)
        file = msoffcrypto.OfficeFile(encrypted_buffer)
        file.load_key(password=password)
        decrypted_buffer = BytesIO()
        file.decrypt(decrypted_buffer)
        decrypted_buffer.seek(0)
        return decrypted_buffer.read()
    except Exception as e:
        raise ValueError(f"Failed to decrypt file: {e}") from e
