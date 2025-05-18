import os
import shutil
from pathlib import Path


def transfer_certifikatat():

    certifikatat = {
        "client.crt": "/home/erisasollova/client.crt",
        "client.key": "/home/erisasollova/client.key",
        "server.crt": "/home/erisasollova/server.crt",
        "server.key": "/home/erisasollova/server.key"
    }


    dest_folder = "/home/erisasollova/PycharmProjects/Gr_18-DataSecurity-Nenshkrime_dhe_Celesa/projekti/certifikata"


    Path(dest_folder).mkdir(parents=True, exist_ok=True)

    print(" Transferimi i certifikatave...")

    for emri, burimi in certifikatat.items():
        dest_path = os.path.join(dest_folder, emri)
        try:
            shutil.copy2(burimi, dest_path)
            if emri.endswith('.key'):
                os.chmod(dest_path, 0o600)  # Leje te kufizuara per çelesat
            print(f" {burimi} → {dest_path}")
        except Exception as e:
            print(f" Gabim me {emri}: {e}")

    print("\n Transferimi i perfunduar!")


if __name__ == "__main__":
    transfer_certifikatat()