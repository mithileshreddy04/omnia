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

"""Test security of integration test configuration."""

import pytest
import string

from tests.integration.conftest import IntegrationTestConfig, generate_secure_test_password


@pytest.mark.integration
class TestIntegrationConfigSecurity:
    """Test suite for integration test configuration security."""

    def test_vault_password_strength(self):
        """Test that vault password meets security requirements."""
        password = IntegrationTestConfig.get_vault_password()
        
        # Should be at least 24 characters
        assert len(password) >= 24
        
        # Should contain at least one lowercase letter
        assert any(c.islower() for c in password)
        
        # Should contain at least one uppercase letter
        assert any(c.isupper() for c in password)
        
        # Should contain at least one digit
        assert any(c.isdigit() for c in password)
        
        # Should contain at least one special character
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        assert any(c in special_chars for c in password)
        
        # Should not contain predictable patterns
        assert "password" not in password.lower()
        assert "test" not in password.lower()
        assert "123" not in password

    def test_auth_password_strength(self):
        """Test that auth password meets security requirements."""
        password = IntegrationTestConfig.get_auth_password()
        
        # Should be at least 24 characters
        assert len(password) >= 24
        
        # Should contain at least one lowercase letter
        assert any(c.islower() for c in password)
        
        # Should contain at least one uppercase letter
        assert any(c.isupper() for c in password)
        
        # Should contain at least one digit
        assert any(c.isdigit() for c in password)
        
        # Should contain at least one special character
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        assert any(c in special_chars for c in password)

    def test_passwords_are_unique(self):
        """Test that vault and auth passwords are different."""
        vault_password = IntegrationTestConfig.get_vault_password()
        auth_password = IntegrationTestConfig.get_auth_password()
        assert vault_password != auth_password

    def test_generate_secure_test_password_function(self):
        """Test the password generation function directly."""
        # Test default length
        password1 = generate_secure_test_password()
        assert len(password1) == 24
        
        # Test custom length
        password2 = generate_secure_test_password(16)
        assert len(password2) == 16
        
        # Test minimum length validation
        with pytest.raises(ValueError):
            generate_secure_test_password(8)
        
        # Test uniqueness
        password3 = generate_secure_test_password(24)
        assert password1 != password2 != password3
        
        # Test character requirements
        for password in [password1, password2, password3]:
            assert any(c.islower() for c in password)
            assert any(c.isupper() for c in password)
            assert any(c.isdigit() for c in password)
            special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            assert any(c in special_chars for c in password)

    def test_username_is_not_secret(self):
        """Test that username is not a secret value."""
        username = IntegrationTestConfig.AUTH_USERNAME
        assert username == "build_stream_registrar"
        assert "password" not in username.lower()
        assert "secret" not in username.lower()
