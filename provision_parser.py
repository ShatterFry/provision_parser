import argparse
from cryptography import x509
import pathlib
import plistlib
import subprocess
import zipfile

def parse_provision(ipa_path):
    ipa_path = pathlib.Path(ipa_path)
    if not ipa_path.is_file() or ipa_path.suffix != ".ipa" or not zipfile.is_zipfile(ipa_path):
        raise Exception(f"Invalid input file {ipa_path}")
    
    with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
        mobile_provision_arch_path = None
        file_names_list = zip_ref.namelist()
        for name in file_names_list:
            if name.startswith("Payload/") and name.endswith(".app/embedded.mobileprovision"):
                mobile_provision_arch_path = name
                break
        if not mobile_provision_arch_path:
            raise Exception("Couldn't find a mobileprovision in ipa")
        print(f"Mobile provision: {mobile_provision_arch_path}")

        with zip_ref.open(mobile_provision_arch_path, "r") as f:
            mobileprovision = f.read()
            proc = subprocess.run("openssl cms -inform DER -verify -noverify", input=mobileprovision, capture_output=True, check=True)
            provision_decoded = proc.stdout.decode()
            print(f"Provision data:\n{provision_decoded}")
            plist_data = plistlib.loads(provision_decoded)

            developer_certificates = plist_data["DeveloperCertificates"]
            print("\nDeveloper certificates:")
            for cert_bytes in developer_certificates:
                cert_decoded = x509.load_der_x509_certificate(cert_bytes)
                print(f"Subject: {cert_decoded.subject}")
                print(f"Serial number: {cert_decoded.serial_number}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("ipa_path", type=str)
    parser.set_defaults(func=parse_provision)
    args = parser.parse_args()
    args.func(args.ipa_path)