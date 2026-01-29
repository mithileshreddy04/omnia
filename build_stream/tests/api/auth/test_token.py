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

"""Integration tests for POST /api/v1/auth/token endpoint."""

from unittest.mock import MagicMock, patch

import pytest
from fastapi import status


@pytest.mark.integration
class TestTokenEndpoint:
    """Test suite for POST /api/v1/auth/token endpoint."""

    TOKEN_URL = "/api/v1/auth/token"

    def test_token_valid_credentials_returns_200(self, test_client, mock_vault_client):
        """Test successful token request with valid credentials."""
        mock_vault_client.get_oauth_clients.return_value = {
            "bld_test123": {
                "client_name": "test-client",
                "client_secret_hash": "$argon2id$v=19$m=65536,t=3,p=4$test$hash",
                "allowed_scopes": ["catalog:read", "catalog:write"],
                "is_active": True,
            }
        }

        with patch("api.auth.service.verify_password", return_value=True):
            with patch("api.auth.service.JWTHandler") as mock_jwt:
                mock_jwt_instance = MagicMock()
                mock_jwt_instance.create_access_token.return_value = (
                    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.token",
                    3600,
                )
                mock_jwt.return_value = mock_jwt_instance

                response = test_client.post(
                    self.TOKEN_URL,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": "bld_test123",
                        "client_secret": "bld_s_testsecret",
                    },
                )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "Bearer"
        assert data["expires_in"] == 3600
        assert "scope" in data

    def test_token_missing_grant_type_returns_422(self, test_client):
        """Test that missing grant_type returns 422."""
        response = test_client.post(
            self.TOKEN_URL,
            data={
                "client_id": "bld_test123",
                "client_secret": "bld_s_testsecret",
            },
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_token_unsupported_grant_type_returns_400(self, test_client):
        """Test that unsupported grant_type returns 400."""
        response = test_client.post(
            self.TOKEN_URL,
            data={
                "grant_type": "password",  # Not supported
                "client_id": "bld_test123",
                "client_secret": "bld_s_testsecret",
            },
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = response.json()
        assert data["detail"]["error"] == "unsupported_grant_type"

    def test_token_missing_client_id_returns_400(self, test_client):
        """Test that missing client_id returns 400."""
        response = test_client.post(
            self.TOKEN_URL,
            data={
                "grant_type": "client_credentials",
                "client_secret": "bld_s_testsecret",
            },
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = response.json()
        assert data["detail"]["error"] == "invalid_request"

    def test_token_missing_client_secret_returns_400(self, test_client):
        """Test that missing client_secret returns 400."""
        response = test_client.post(
            self.TOKEN_URL,
            data={
                "grant_type": "client_credentials",
                "client_id": "bld_test123",
            },
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = response.json()
        assert data["detail"]["error"] == "invalid_request"

    def test_token_invalid_client_returns_401(self, test_client, mock_vault_client):
        """Test that invalid client credentials returns 401."""
        mock_vault_client.get_oauth_clients.return_value = {}  # No clients

        response = test_client.post(
            self.TOKEN_URL,
            data={
                "grant_type": "client_credentials",
                "client_id": "bld_unknown",
                "client_secret": "bld_s_testsecret",
            },
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        data = response.json()
        assert data["detail"]["error"] == "invalid_client"

    def test_token_wrong_secret_returns_401(self, test_client, mock_vault_client):
        """Test that wrong client secret returns 401."""
        mock_vault_client.get_oauth_clients.return_value = {
            "bld_test123": {
                "client_name": "test-client",
                "client_secret_hash": "$argon2id$v=19$m=65536,t=3,p=4$test$hash",
                "allowed_scopes": ["catalog:read"],
                "is_active": True,
            }
        }

        with patch("api.auth.service.verify_password", return_value=False):
            response = test_client.post(
                self.TOKEN_URL,
                data={
                    "grant_type": "client_credentials",
                    "client_id": "bld_test123",
                    "client_secret": "bld_s_wrongsecret",
                },
            )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        data = response.json()
        assert data["detail"]["error"] == "invalid_client"

    def test_token_disabled_client_returns_403(self, test_client, mock_vault_client):
        """Test that disabled client returns 403."""
        mock_vault_client.get_oauth_clients.return_value = {
            "bld_test123": {
                "client_name": "test-client",
                "client_secret_hash": "$argon2id$v=19$m=65536,t=3,p=4$test$hash",
                "allowed_scopes": ["catalog:read"],
                "is_active": False,  # Disabled
            }
        }

        response = test_client.post(
            self.TOKEN_URL,
            data={
                "grant_type": "client_credentials",
                "client_id": "bld_test123",
                "client_secret": "bld_s_testsecret",
            },
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN
        data = response.json()
        assert data["detail"]["error"] == "client_disabled"

    def test_token_invalid_scope_returns_400(self, test_client, mock_vault_client):
        """Test that requesting unauthorized scope returns 400."""
        mock_vault_client.get_oauth_clients.return_value = {
            "bld_test123": {
                "client_name": "test-client",
                "client_secret_hash": "$argon2id$v=19$m=65536,t=3,p=4$test$hash",
                "allowed_scopes": ["catalog:read"],  # Only catalog:read allowed
                "is_active": True,
            }
        }

        with patch("api.auth.service.verify_password", return_value=True):
            response = test_client.post(
                self.TOKEN_URL,
                data={
                    "grant_type": "client_credentials",
                    "client_id": "bld_test123",
                    "client_secret": "bld_s_testsecret",
                    "scope": "admin:write",  # Not allowed
                },
            )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = response.json()
        assert data["detail"]["error"] == "invalid_scope"

    def test_token_with_valid_scope_returns_200(self, test_client, mock_vault_client):
        """Test token request with valid specific scope."""
        mock_vault_client.get_oauth_clients.return_value = {
            "bld_test123": {
                "client_name": "test-client",
                "client_secret_hash": "$argon2id$v=19$m=65536,t=3,p=4$test$hash",
                "allowed_scopes": ["catalog:read", "catalog:write"],
                "is_active": True,
            }
        }

        with patch("api.auth.service.verify_password", return_value=True):
            with patch("api.auth.service.JWTHandler") as mock_jwt:
                mock_jwt_instance = MagicMock()
                mock_jwt_instance.create_access_token.return_value = (
                    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.token",
                    3600,
                )
                mock_jwt.return_value = mock_jwt_instance

                response = test_client.post(
                    self.TOKEN_URL,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": "bld_test123",
                        "client_secret": "bld_s_testsecret",
                        "scope": "catalog:read",
                    },
                )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["scope"] == "catalog:read"

    def test_token_response_contains_all_fields(self, test_client, mock_vault_client):
        """Test that token response contains all required fields."""
        mock_vault_client.get_oauth_clients.return_value = {
            "bld_test123": {
                "client_name": "test-client",
                "client_secret_hash": "$argon2id$v=19$m=65536,t=3,p=4$test$hash",
                "allowed_scopes": ["catalog:read"],
                "is_active": True,
            }
        }

        with patch("api.auth.service.verify_password", return_value=True):
            with patch("api.auth.service.JWTHandler") as mock_jwt:
                mock_jwt_instance = MagicMock()
                mock_jwt_instance.create_access_token.return_value = (
                    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.token",
                    3600,
                )
                mock_jwt.return_value = mock_jwt_instance

                response = test_client.post(
                    self.TOKEN_URL,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": "bld_test123",
                        "client_secret": "bld_s_testsecret",
                    },
                )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert "access_token" in data
        assert "token_type" in data
        assert "expires_in" in data
        assert "scope" in data

        assert data["token_type"] == "Bearer"
        assert isinstance(data["expires_in"], int)
        assert data["expires_in"] > 0

    def test_token_content_type_form_urlencoded(self, test_client, mock_vault_client):
        """Test that token endpoint accepts application/x-www-form-urlencoded."""
        mock_vault_client.get_oauth_clients.return_value = {
            "bld_test123": {
                "client_name": "test-client",
                "client_secret_hash": "$argon2id$v=19$m=65536,t=3,p=4$test$hash",
                "allowed_scopes": ["catalog:read"],
                "is_active": True,
            }
        }

        with patch("api.auth.service.verify_password", return_value=True):
            with patch("api.auth.service.JWTHandler") as mock_jwt:
                mock_jwt_instance = MagicMock()
                mock_jwt_instance.create_access_token.return_value = (
                    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.token",
                    3600,
                )
                mock_jwt.return_value = mock_jwt_instance

                response = test_client.post(
                    self.TOKEN_URL,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": "bld_test123",
                        "client_secret": "bld_s_testsecret",
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

        assert response.status_code == status.HTTP_200_OK
