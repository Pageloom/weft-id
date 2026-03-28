"""Tests for passphrase generation wordlist utility."""

from utils.wordlist import WORDLIST, generate_passphrase


class TestWordlist:
    """Tests for the WORDLIST constant."""

    def test_wordlist_has_2048_words(self):
        assert len(WORDLIST) == 2048

    def test_wordlist_all_lowercase(self):
        for word in WORDLIST:
            assert word == word.lower(), f"Word '{word}' is not lowercase"

    def test_wordlist_no_duplicates(self):
        assert len(WORDLIST) == len(set(WORDLIST))

    def test_wordlist_word_length_range(self):
        for word in WORDLIST:
            assert 3 <= len(word) <= 7, f"Word '{word}' has {len(word)} chars"

    def test_wordlist_only_alpha(self):
        for word in WORDLIST:
            assert word.isalpha(), f"Word '{word}' contains non-alpha chars"


class TestGeneratePassphrase:
    """Tests for generate_passphrase()."""

    def test_default_six_words(self):
        passphrase = generate_passphrase()
        words = passphrase.split("-")
        assert len(words) == 6

    def test_custom_word_count(self):
        passphrase = generate_passphrase(word_count=4)
        assert len(passphrase.split("-")) == 4

    def test_words_from_wordlist(self):
        passphrase = generate_passphrase()
        wordlist_set = set(WORDLIST)
        for word in passphrase.split("-"):
            assert word in wordlist_set

    def test_passphrases_are_unique(self):
        """Multiple passphrases should be different (statistical)."""
        passphrases = {generate_passphrase() for _ in range(100)}
        assert len(passphrases) == 100

    def test_passphrase_format(self):
        passphrase = generate_passphrase()
        assert passphrase == passphrase.lower()
        assert "-" in passphrase
        assert all(c.isalpha() or c == "-" for c in passphrase)
