import subprocess
import sys

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

def main():
    try:
        # Liste des paquets externes à installer
        packages = ["Pillow", "paramiko"]
        for package in packages:
            install(package)
        print("Toutes les dépendances ont été installées avec succès.")
    except Exception as e:
        print(f"Une erreur s'est produite lors de l'installation des dépendances: {e}")

if __name__ == "__main__":
    main()
