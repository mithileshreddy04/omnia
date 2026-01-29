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

"""Unit tests for token generation service methods."""

from unittest.mock import MagicMock, patch

import pytest

from api.auth.service import (
    AuthService,
    ClientDisabledError,
    InvalidClientError,
    InvalidScopeError,
    TokenCreationError,
    TokenResult,
)


@pytest.fixture
def mock_vault_client():
    """Create a mock vault client."""
    mock = MagicMock()
    mock.get_oauth_clients.return_value = {
        "bld_test123": {
            "client_name": "test-client",
            "client_secret_hash": "$argon2id$v=19$m=65536,t=3,p=4$dGVzdHNhbHQ$testhash",
            "allowed_scopes": ["catalog:read", "catalog:write"],
            "is_active": True,
        }
    }
    return mock


@pytest.fixture
def mock_jwt_handler():
    """Create a mock JWT handler."""
    mock = MagicMock()
    mock.create_access_token.return_value = ("mock.jwt.token", 3600)
    return mock


@pytest.fixture
def auth_service(mock_vault_client, mock_jwt_handler):
    """Create AuthService with mocked dependencies."""
    return AuthService(vault_client=mock_vault_client, jwt_handler=mock_jwt_handler)


@pytest.mark.unit
class TestVerifyClientCredentials:
    """Test suite for verify_client_credentials method."""

    def test_verify_valid_credentials(self, auth_service, mock_vault_client):
        """Test verification with valid client credentials."""
        with patch("api.auth.service.verify_password", return_value=True):
            result = auth_service.verify_client_credentials(
                client_id="bld_test123",
                client_secret="valid_secret",
            )

        assert result["client_name"] == "test-client"
        assert result["allowed_scopes"] == ["catalog:read", "catalog:write"]

    def test_verify_unknown_client_raises_error(self, auth_service):
        """Test that unknown client_id raises InvalidClientError."""
        with pytest.raises(InvalidClientError):
            auth_service.verify_client_credentials(
                client_id="bld_unknown",
                client_secret="any_secret",
            )

    def test_verify_invalid_secret_raises_error(self, auth_service):
        """Test that invalid secret raises InvalidClientError."""
        with patch("api.auth.service.verify_password", return_value=False):
            with pytest.raises(InvalidClientError):
                auth_service.verify_client_credentials(
                    client_id="bld_test123",
                    client_secret="wrong_secret",
                )

    def test_verify_disabled_client_raises_error(self, auth_service, mock_vault_client):
        """Test that disabled client raises ClientDisabledError."""
        mock_vault_client.get_oauth_clients.return_value = {
            "bld_test123": {
                "client_name": "test-client",
                "client_secret_hash": "$argon2id$...",
                "allowed_scopes": ["catalog:read"],
                "is_active": False,  # Disabled
            }
        }

        with pytest.raises(ClientDisabledError):
            auth_service.verify_client_credentials(
                client_id="bld_test123",
                client_secret="any_secret",
            )

    def test_verify_client_without_hash_raises_error(self, auth_service, mock_vault_client):
        """Test that client without secret hash raises InvalidClientError."""
        mock_vault_client.get_oauth_clients.return_value = {
            "bld_test123": {
                "client_name": "test-client",
                "allowed_scopes": ["catalog:read"],
                "is_active": True,
                # No client_secret_hash
            }
        }

        with pytest.raises(InvalidClientError):
            auth_service.verify_client_credentials(
                client_id="bld_test123",
                client_secret="any_secret",
            )

    def test_verify_vault_not_found_raises_error(self, auth_service, mock_vault_client):
        """Test that vault not found raises InvalidClientError."""
        from api.auth.vault_client import VaultNotFoundError

        mock_vault_client.get_oauth_clients.side_effect = VaultNotFoundError("Not found")

        with pytest.raises(InvalidClientError):
            auth_service.verify_client_credentials(
                client_id="bld_test123",
                client_secret="any_secret",
            )

    def test_verify_vault_decrypt_error_raises_error(self, auth_service, mock_vault_client):
        """Test that vault decrypt error raises InvalidClientError."""
        from api.auth.vault_client import VaultDecryptError

        mock_vault_client.get_oauth_clients.side_effect = VaultDecryptError("Decrypt failed")

        with pytest.raises(InvalidClientError):
            auth_service.verify_client_credentials(
                client_id="bld_test123",
                client_secret="any_secret",
            )


@pytest.mark.unit
class TestGenerateToken:
    """Test suite for generate_token method."""

    def test_generate_token_success(self, auth_service, mock_jwt_handler):
        """Test successful token generation."""
        with patch("api.auth.service.verify_password", return_value=True):
            result = auth_service.generate_token(
                client_id="bld_test123",
                client_secret="valid_secret",
            )

        assert isinstance(result, TokenResult)
        assert result.access_token == "mock.jwt.token"
        assert result.token_type == "Bearer"
        assert result.expires_in == 3600
        assert result.scope == "catalog:read catalog:write"

        mock_jwt_handler.create_access_token.assert_called_once_with(
            client_id="bld_test123",
            client_name="test-client",
            scopes=["catalog:read", "catalog:write"],
        )

    def test_generate_token_with_requested_scope(self, auth_service, mock_jwt_handler):
        """Test token generation with specific requested scope."""
        with patch("api.auth.service.verify_password", return_value=True):
            result = auth_service.generate_token(
                client_id="bld_test123",
                client_secret="valid_secret",
                requested_scope="catalog:read",
            )

        assert result.scope == "catalog:read"
        mock_jwt_handler.create_access_token.assert_called_once_with(
            client_id="bld_test123",
            client_name="test-client",
            scopes=["catalog:read"],
        )

    def test_generate_token_with_multiple_requested_scopes(self, auth_service, mock_jwt_handler):
        """Test token generation with multiple requested scopes."""
        with patch("api.auth.service.verify_password", return_value=True):
            result = auth_service.generate_token(
                client_id="bld_test123",
                client_secret="valid_secret",
                requested_scope="catalog:read catalog:write",
            )

        mock_jwt_handler.create_access_token.assert_called_once_with(
            client_id="bld_test123",
            client_name="test-client",
            scopes=["catalog:read", "catalog:write"],
        )

    def test_generate_token_unauthorized_scope_raises_error(self, auth_service):
        """Test that requesting unauthorized scope raises InvalidScopeError."""
        with patch("api.auth.service.verify_password", return_value=True):
            with pytest.raises(InvalidScopeError) as exc_info:
                auth_service.generate_token(
                    client_id="bld_test123",
                    client_secret="valid_secret",
                    requested_scope="admin:write",  # Not in allowed_scopes
                )

        assert "admin:write" in str(exc_info.value)

    def test_generate_token_invalid_credentials_raises_error(self, auth_service):
        """Test that invalid credentials raises InvalidClientError."""
        with patch("api.auth.service.verify_password", return_value=False):
            with pytest.raises(InvalidClientError):
                auth_service.generate_token(
                    client_id="bld_test123",
                    client_secret="wrong_secret",
                )

    def test_generate_token_jwt_creation_error_raises_error(
        self, auth_service, mock_jwt_handler
    ):
        """Test that JWT creation error raises TokenCreationError."""
        from api.auth.jwt_handler import JWTCreationError as JWTCreationErr

        mock_jwt_handler.create_access_token.side_effect = JWTCreationErr("Key not found")

        with patch("api.auth.service.verify_password", return_value=True):
            with pytest.raises(TokenCreationError):
                auth_service.generate_token(
                    client_id="bld_test123",
                    client_secret="valid_secret",
                )

    def test_generate_token_uses_default_scopes_when_none_requested(
        self, auth_service, mock_vault_client, mock_jwt_handler
    ):
        """Test that default scopes are used when none requested."""
        mock_vault_client.get_oauth_clients.return_value = {
            "bld_test123": {
                "client_name": "test-client",
                "client_secret_hash": "$argon2id$...",
                "allowed_scopes": ["catalog:read"],
                "is_active": True,
            }
        }

        with patch("api.auth.service.verify_password", return_value=True):
            result = auth_service.generate_token(
                client_id="bld_test123",
                client_secret="valid_secret",
                requested_scope=None,
            )

        mock_jwt_handler.create_access_token.assert_called_once_with(
            client_id="bld_test123",
            client_name="test-client",
            scopes=["catalog:read"],
        )
