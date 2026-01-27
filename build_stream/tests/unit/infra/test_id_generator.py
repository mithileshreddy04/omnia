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

"""Unit tests for UUIDv7Generator infrastructure component."""

import re

from build_stream.infra.id_generator import UUIDv7Generator


class TestUUIDv7Generator:
    """Tests covering UUIDv7Generator behavior."""

    def test_generate_returns_valid_job_id(self) -> None:
        """Generator should produce a JobId string of expected length."""
        generator = UUIDv7Generator()

        job_id = generator.generate()

        assert isinstance(job_id.value, str)
        assert len(job_id.value) == 36

    def test_generate_returns_uuid_v7_format(self) -> None:
        """Generated JobId must conform to UUID v7 format."""
        generator = UUIDv7Generator()

        job_id = generator.generate()

        assert re.match(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            job_id.value.lower(),
        )

    def test_generate_is_unique(self) -> None:
        """Generator should yield unique IDs over multiple invocations."""
        generator = UUIDv7Generator()

        generated = {generator.generate().value for _ in range(50)}

        assert len(generated) == 50
