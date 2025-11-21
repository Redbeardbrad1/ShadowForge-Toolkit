import argparse
from shadowforge_pkg.shield import activate_shield

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ShadowForge-Toolkit – Ethical pentest beast")
    parser.add_argument("command", choices=["shield"], help="Module to run")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP")
    args = parser.parse_args()

    if args.command == "shield":
        print("Forging ghost mode...")
        activate_shield(target=args.target)