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

"""Unit tests for JWT handler module."""

import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from jose import jwt

from api.auth.jwt_handler import (
    JWTConfig,
    JWTCreationError,
    JWTExpiredError,
    JWTHandler,
    JWTInvalidSignatureError,
    JWTValidationError,
)


@pytest.fixture
def rsa_key_pair():
    """Generate RSA key pair for testing."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_pem.decode("utf-8"), public_pem.decode("utf-8")


@pytest.fixture
def jwt_config(rsa_key_pair, tmp_path):
    """Create JWT config with temporary key files."""
    private_key, public_key = rsa_key_pair

    private_key_path = tmp_path / "jwt_private.pem"
    public_key_path = tmp_path / "jwt_public.pem"

    private_key_path.write_text(private_key)
    public_key_path.write_text(public_key)

    return JWTConfig(
        private_key_path=str(private_key_path),
        public_key_path=str(public_key_path),
        algorithm="RS256",
        access_token_expire_minutes=60,
        issuer="build-stream-api",
        audience="build-stream-api",
        key_id="test-key-2026-01",
    )


@pytest.fixture
def jwt_handler(jwt_config):
    """Create JWT handler with test config."""
    return JWTHandler(config=jwt_config)


@pytest.mark.unit
class TestJWTConfig:
    """Test suite for JWTConfig class."""

    def test_from_env_defaults(self):
        """Test JWTConfig.from_env() uses default values."""
        with patch.dict("os.environ", {}, clear=True):
            config = JWTConfig.from_env()

        assert config.private_key_path == "/etc/omnia/keys/jwt_private.pem"
        assert config.public_key_path == "/etc/omnia/keys/jwt_public.pem"
        assert config.algorithm == "RS256"
        assert config.access_token_expire_minutes == 60
        assert config.issuer == "build-stream-api"
        assert config.audience == "build-stream-api"

    def test_from_env_custom_values(self):
        """Test JWTConfig.from_env() uses environment variables."""
        env_vars = {
            "JWT_PRIVATE_KEY_PATH": "/custom/private.pem",
            "JWT_PUBLIC_KEY_PATH": "/custom/public.pem",
            "JWT_ALGORITHM": "RS512",
            "JWT_ACCESS_TOKEN_EXPIRE_MINUTES": "120",
            "JWT_ISSUER": "custom-issuer",
            "JWT_AUDIENCE": "custom-audience",
            "JWT_KEY_ID": "custom-key-id",
        }
        with patch.dict("os.environ", env_vars):
            config = JWTConfig.from_env()

        assert config.private_key_path == "/custom/private.pem"
        assert config.public_key_path == "/custom/public.pem"
        assert config.algorithm == "RS512"
        assert config.access_token_expire_minutes == 120
        assert config.issuer == "custom-issuer"
        assert config.audience == "custom-audience"
        assert config.key_id == "custom-key-id"


@pytest.mark.unit
class TestJWTHandlerTokenCreation:
    """Test suite for JWT token creation."""

    def test_create_access_token_returns_valid_jwt(self, jwt_handler):
        """Test that create_access_token returns a valid JWT."""
        token, expires_in = jwt_handler.create_access_token(
            client_id="bld_test123",
            client_name="test-client",
            scopes=["catalog:read", "catalog:write"],
        )

        assert token is not None
        assert isinstance(token, str)
        assert token.count(".") == 2  # JWT has 3 parts
        assert expires_in == 3600  # 60 minutes in seconds

    def test_create_access_token_contains_correct_claims(self, jwt_handler, jwt_config):
        """Test that created token contains correct claims."""
        token, _ = jwt_handler.create_access_token(
            client_id="bld_test123",
            client_name="test-client",
            scopes=["catalog:read"],
        )

        # Decode without verification to check claims
        claims = jwt.get_unverified_claims(token)

        assert claims["iss"] == "build-stream-api"
        assert claims["sub"] == "bld_test123"
        assert claims["aud"] == "build-stream-api"
        assert claims["scope"] == "catalog:read"
        assert claims["client_name"] == "test-client"
        assert "iat" in claims
        assert "exp" in claims
        assert "nbf" in claims
        assert "jti" in claims

    def test_create_access_token_has_correct_headers(self, jwt_handler, jwt_config):
        """Test that created token has correct headers."""
        token, _ = jwt_handler.create_access_token(
            client_id="bld_test123",
            client_name="test-client",
            scopes=["catalog:read"],
        )

        headers = jwt.get_unverified_header(token)

        assert headers["alg"] == "RS256"
        assert headers["typ"] == "JWT"
        assert headers["kid"] == "test-key-2026-01"

    def test_create_access_token_multiple_scopes(self, jwt_handler):
        """Test token creation with multiple scopes."""
        token, _ = jwt_handler.create_access_token(
            client_id="bld_test123",
            client_name="test-client",
            scopes=["catalog:read", "catalog:write", "admin:read"],
        )

        claims = jwt.get_unverified_claims(token)
        assert claims["scope"] == "catalog:read catalog:write admin:read"

    def test_create_access_token_unique_jti(self, jwt_handler):
        """Test that each token has a unique jti."""
        token1, _ = jwt_handler.create_access_token(
            client_id="bld_test123",
            client_name="test-client",
            scopes=["catalog:read"],
        )
        token2, _ = jwt_handler.create_access_token(
            client_id="bld_test123",
            client_name="test-client",
            scopes=["catalog:read"],
        )

        claims1 = jwt.get_unverified_claims(token1)
        claims2 = jwt.get_unverified_claims(token2)

        assert claims1["jti"] != claims2["jti"]

    def test_create_access_token_missing_private_key_raises_error(self, jwt_config):
        """Test that missing private key raises JWTCreationError."""
        jwt_config.private_key_path = "/nonexistent/key.pem"
        handler = JWTHandler(config=jwt_config)

        with pytest.raises(JWTCreationError):
            handler.create_access_token(
                client_id="bld_test123",
                client_name="test-client",
                scopes=["catalog:read"],
            )


@pytest.mark.unit
class TestJWTHandlerTokenValidation:
    """Test suite for JWT token validation."""

    def test_validate_token_returns_token_data(self, jwt_handler):
        """Test that validate_token returns correct TokenData."""
        token, _ = jwt_handler.create_access_token(
            client_id="bld_test123",
            client_name="test-client",
            scopes=["catalog:read", "catalog:write"],
        )

        token_data = jwt_handler.validate_token(token)

        assert token_data.client_id == "bld_test123"
        assert token_data.client_name == "test-client"
        assert token_data.scopes == ["catalog:read", "catalog:write"]
        assert token_data.token_id is not None

    def test_validate_token_expired_raises_error(self, jwt_config, rsa_key_pair):
        """Test that expired token raises JWTExpiredError."""
        # Create handler with very short expiry
        jwt_config.access_token_expire_minutes = 0  # Immediate expiry
        handler = JWTHandler(config=jwt_config)

        # Create token that expires immediately
        private_key, _ = rsa_key_pair
        now = int(time.time())
        claims = {
            "iss": "build-stream-api",
            "sub": "bld_test123",
            "aud": "build-stream-api",
            "iat": now - 3700,  # Issued over an hour ago
            "exp": now - 100,  # Expired 100 seconds ago
            "nbf": now - 3700,
            "jti": "test-jti",
            "scope": "catalog:read",
            "client_name": "test-client",
        }
        expired_token = jwt.encode(claims, private_key, algorithm="RS256")

        with pytest.raises(JWTExpiredError):
            handler.validate_token(expired_token)

    def test_validate_token_invalid_signature_raises_error(self, jwt_handler, tmp_path):
        """Test that invalid signature raises JWTInvalidSignatureError."""
        # Create a token with a different key
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        other_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        other_private_pem = other_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        now = int(time.time())
        claims = {
            "iss": "build-stream-api",
            "sub": "bld_test123",
            "aud": "build-stream-api",
            "iat": now,
            "exp": now + 3600,
            "nbf": now,
            "jti": "test-jti",
            "scope": "catalog:read",
            "client_name": "test-client",
        }
        bad_token = jwt.encode(claims, other_private_pem, algorithm="RS256")

        with pytest.raises(JWTInvalidSignatureError):
            jwt_handler.validate_token(bad_token)

    def test_validate_token_wrong_issuer_raises_error(self, jwt_handler, rsa_key_pair):
        """Test that wrong issuer raises JWTValidationError."""
        private_key, _ = rsa_key_pair
        now = int(time.time())
        claims = {
            "iss": "wrong-issuer",  # Wrong issuer
            "sub": "bld_test123",
            "aud": "build-stream-api",
            "iat": now,
            "exp": now + 3600,
            "nbf": now,
            "jti": "test-jti",
            "scope": "catalog:read",
            "client_name": "test-client",
        }
        bad_token = jwt.encode(claims, private_key, algorithm="RS256")

        with pytest.raises(JWTValidationError):
            jwt_handler.validate_token(bad_token)

    def test_validate_token_wrong_audience_raises_error(self, jwt_handler, rsa_key_pair):
        """Test that wrong audience raises JWTValidationError."""
        private_key, _ = rsa_key_pair
        now = int(time.time())
        claims = {
            "iss": "build-stream-api",
            "sub": "bld_test123",
            "aud": "wrong-audience",  # Wrong audience
            "iat": now,
            "exp": now + 3600,
            "nbf": now,
            "jti": "test-jti",
            "scope": "catalog:read",
            "client_name": "test-client",
        }
        bad_token = jwt.encode(claims, private_key, algorithm="RS256")

        with pytest.raises(JWTValidationError):
            jwt_handler.validate_token(bad_token)

    def test_validate_token_missing_public_key_raises_error(self, jwt_config):
        """Test that missing public key raises JWTValidationError."""
        jwt_config.public_key_path = "/nonexistent/key.pem"
        handler = JWTHandler(config=jwt_config)

        with pytest.raises(JWTValidationError):
            handler.validate_token("some.fake.token")
