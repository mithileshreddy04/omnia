# Copyright 2026 Dell Inc. or its subsidiaries. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit tests for password_handler module."""

import pytest

from api.auth.password_handler import (
    generate_client_id,
    generate_client_secret,
    generate_credentials,
    hash_password,
    verify_password,
)


@pytest.mark.unit
class TestPasswordHashing:
    """Test suite for password hashing functions."""

    def test_hash_password_returns_argon2_hash(self):
        """Test that hash_password returns Argon2id hash."""
        password = "test_password"
        hashed = hash_password(password)

        assert hashed.startswith("$argon2id$")
        assert password not in hashed

    def test_hash_password_different_for_same_input(self):
        """Test that hashing same password twice produces different hashes."""
        password = "test_password"
        hash1 = hash_password(password)
        hash2 = hash_password(password)

        assert hash1 != hash2

    def test_verify_password_correct_password(self):
        """Test verify_password returns True for correct password."""
        password = "correct_password"
        hashed = hash_password(password)

        assert verify_password(password, hashed) is True

    def test_verify_password_incorrect_password(self):
        """Test verify_password returns False for incorrect password."""
        password = "correct_password"
        hashed = hash_password(password)

        assert verify_password("wrong_password", hashed) is False

    def test_verify_password_invalid_hash(self):
        """Test verify_password returns False for invalid hash."""
        assert verify_password("password", "invalid_hash") is False


@pytest.mark.unit
class TestCredentialGeneration:
    """Test suite for credential generation functions."""

    def test_generate_client_id_format(self):
        """Test client_id has correct format."""
        client_id = generate_client_id()

        assert client_id.startswith("bld_")
        assert len(client_id) == 36

    def test_generate_client_id_unique(self):
        """Test client_id is unique each time."""
        ids = [generate_client_id() for _ in range(100)]

        assert len(set(ids)) == 100

    def test_generate_client_secret_format(self):
        """Test client_secret has correct format."""
        client_secret = generate_client_secret()

        assert client_secret.startswith("bld_s_")
        assert len(client_secret) > 40

    def test_generate_client_secret_unique(self):
        """Test client_secret is unique each time."""
        secrets = [generate_client_secret() for _ in range(100)]

        assert len(set(secrets)) == 100

    def test_generate_credentials_returns_tuple(self):
        """Test generate_credentials returns correct tuple."""
        client_id, client_secret, hashed_secret = generate_credentials()

        assert client_id.startswith("bld_")
        assert client_secret.startswith("bld_s_")
        assert hashed_secret.startswith("$argon2id$")

    def test_generate_credentials_secret_verifiable(self):
        """Test that generated secret can be verified against hash."""
        _, client_secret, hashed_secret = generate_credentials()

        assert verify_password(client_secret, hashed_secret) is True
