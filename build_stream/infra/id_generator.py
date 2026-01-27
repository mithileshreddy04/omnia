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

"""Infrastructure layer for JobId generation.

This module provides UUID v7 generation for JobId creation.
TODO: Replace with uuid7 library when available in standard library.
"""

import time
import uuid

from build_stream.core.jobs.exceptions import JobDomainError
from build_stream.core.jobs.repositories import JobIdGenerator, UUIDGenerator
from build_stream.core.jobs.value_objects import JobId

class UUIDv7Generator(JobIdGenerator):
    """Temporary UUID v7 generator implementation.

    This is a fallback implementation until uuid7 is available
    in the Python standard library. Generates time-ordered UUIDs
    compatible with UUID v7 specification.
    """

    def generate(self) -> JobId:
        """Generate a new UUID v7 JobId.

        Returns:
            JobId: A new UUID v7 identifier.

        Raises:
            JobDomainError: If JobId generation fails.
        """
        try:
            return JobId(str(self._uuid7()))
        except ValueError:
            raise
        except Exception as exc:
            raise JobDomainError(f"Failed to generate JobId: {exc}") from exc

    def _uuid7(self) -> uuid.UUID:
        """Generate a UUID v7 using timestamp and random bytes.

        Returns:
            uuid.UUID: A UUID v7 object.
        """
        timestamp_ms = int(time.time() * 1000)
        timestamp_bytes = timestamp_ms.to_bytes(6, byteorder='big')

        random_bytes = uuid.uuid4().bytes

        uuid7_bytes = bytearray(16)
        uuid7_bytes[:6] = timestamp_bytes
        uuid7_bytes[6:] = random_bytes[6:]

        uuid7_bytes[6] = (0x07 << 4) | (uuid7_bytes[6] & 0x0f)
        uuid7_bytes[8] = 0x80 | (uuid7_bytes[8] & 0x3f)

        return uuid.UUID(bytes=bytes(uuid7_bytes))


class UUIDv4Generator(UUIDGenerator):
    """UUID v4 generator for general purpose use.

    Generates random UUID v4 identifiers that can be used for events,
    correlation IDs, or any other purpose requiring a unique identifier.
    """

    def generate(self) -> uuid.UUID:
        """Generate a new UUID v4.

        Returns:
            uuid.UUID: A new UUID v4 object.
        """
        return uuid.uuid4()
