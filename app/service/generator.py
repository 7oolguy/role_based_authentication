import uuid
import time
from typing import Set

def get_guaranteed_unique_uuid(existing_uuids: Set[str] = set()) -> str:
    """
    Generates a UUID and checks for its existence in a set of existing UUIDs.
    It retries until a new, unique UUID is found.

    Args:
        existing_uuids (Set[str]): A set containing all UUIDs that are
                                   already in use and should not be duplicated.

    Returns:
        str: A UUID string that is guaranteed to be unique within the context
             of the existing_uuids set.
    """
    while True:
        # Step 1: Generate a new UUID. We use uuid.uuid4() for its high randomness.
        new_uuid = str(uuid.uuid4())

        # Step 2: Check if the new UUID already exists in our "database" (the set).
        if new_uuid not in existing_uuids:
            # Step 3: If it's not a duplicate, add it to our list and return it.
            existing_uuids.add(new_uuid)
            return new_uuid

        # This part of the code is extremely unlikely to run in practice due to the
        # vast number of possible UUIDs, but it's essential for the guarantee.
        print("Collision detected! Regenerating UUID...")
        time.sleep(0.001)  # Small delay to avoid a tight loop
