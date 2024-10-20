import os
import shutil
import sys
from hashlib import sha256

from pyasice import Container, SignatureVerificationError
from pyasice.exceptions import ContainerError


def main():
    dirname = "containers"
    target = "combined.asice"

    datafiles: list[str] = []
    hashes: list[bytes] = []

    target_container: Container | None = None

    try:
        for file in os.listdir(dirname):
            filename = os.fsdecode(file)
            if not filename.endswith(".asice"):
                continue

            filepath = f"{dirname}/{filename}"
            container = Container.open(filepath)

            container.verify_container()

            if len(container.signature_file_names) > 1:
                print(f"Container '{filename}' contains more than one signature. Skipping...")
                continue

            if len(container.signature_file_names) != 1:
                print(f"Container '{filename}' contains no signatures. Skipping...")
                continue

            if not container.has_data_files():
                print(f"Container '{filename}' has no data files. Skipping...")
                continue

            if len(datafiles) == 0:
                datafiles = container.data_file_names
                for datafile in container.iter_data_files():
                    _, data, _ = datafile
                    hashes.append(sha256(data).digest())

                shutil.copyfile(filepath, target)
                target_container = Container.open(target)
                continue

            # Check if the container contains the expected files.
            if datafiles != container.data_file_names:
                print(f"File mismatch for '{filename}'. Skipping...")
                continue

            # Verify that the files are indeed identical.
            compare_hashes: list[bytes] = []
            for datafile in container.iter_data_files():
                _, data, _ = datafile
                compare_hashes.append(sha256(data).digest())

            if hashes != compare_hashes:
                print(f"File mismatch for '{filename}'. Skipping...")
                continue

            # There should be only one signature.
            for sig in container.iter_signatures():
                target_container.add_signature(sig)

        target_container.save(target)

    except FileNotFoundError as e:
        print(e)
        sys.exit(1)
    except ContainerError as e:
        print(e)
        sys.exit(1)
    except SignatureVerificationError as e:
        print(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
