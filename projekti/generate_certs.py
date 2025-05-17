import os
import shutil
from pathlib import Path


def transfer_certifikatat():
    # Rrugët e burimit (ndryshoni sipas nevojës)
    certifikatat = {
        "client.crt": "/home/erisasollova/client.crt",
        "client.key": "/home/erisasollova/client.key",
        "server.crt": "/home/erisasollova/server.crt",
        "server.key": "/home/erisasollova/server.key"
    }

    # Destinacioni në projekt
    dest_folder = "/home/erisasollova/PycharmProjects/DataSecurity/projekti/certifikata"

    # Krijo folderin nëse nuk ekziston
    Path(dest_folder).mkdir(parents=True, exist_ok=True)

    print("🔄 Transferimi i certifikatave...")

    for emri, burimi in certifikatat.items():
        dest_path = os.path.join(dest_folder, emri)
        try:
            shutil.copy2(burimi, dest_path)
            if emri.endswith('.key'):
                os.chmod(dest_path, 0o600)  # Leje të kufizuara për çelësat
            print(f"✓ {burimi} → {dest_path}")
        except Exception as e:
            print(f"✗ Gabim me {emri}: {e}")

    print("\n✅ Transferimi i përfunduar!")


if __name__ == "__main__":
    transfer_certifikatat()