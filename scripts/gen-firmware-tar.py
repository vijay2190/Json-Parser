#!/usr/bin/env python3

import argparse
import json
import os
import tarfile
from pathlib import Path
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def sign_manifest(private_key_path, manifest_path):
    """Sign the MANIFEST.json using the custom private key."""
    sig_file = manifest_path.with_suffix('.sig')

    # Load the private key
    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  # No password is provided
            backend=default_backend()
        )

    # Read the manifest content (which is a JSON file) to sign
    with open(manifest_path, 'rb') as manifest_file:
        manifest_data = manifest_file.read()

    # Sign the manifest data
    signature = private_key.sign(
        manifest_data,  # Data to sign (must be bytes)
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # Save the signature to a file
    with open(sig_file, 'wb') as sig_obj:
        sig_obj.write(signature)
    
    return sig_file

def calculate_hash(filename):
    """Calculate SHA-512 hash of the filename string."""
    return hashlib.sha512(filename.encode()).hexdigest()

def load_skip_regions(filename):
    """Load SkipRegions.json if available."""
    skip_regions_file = f"../skipRegionsJsonFile/{filename}.SkipRegions.json"

    if os.path.exists(skip_regions_file):
        with open(skip_regions_file, 'r') as skip_file:
            skip_data = json.load(skip_file)
        return skip_data.get("SkipRegions", [])
    return []

def create_json_manifest(machine, compatible, version, extended_version, filenames):
    """Create the JSON manifest with optional SkipRegions.json data."""
    manifest = {
        "MachineName": machine,
        "CompatibleName": compatible,
        "version": version,
        "ExtendedVersion": extended_version,
        "Files": []
    }

    for filename in filenames:
        file_info = {
            "FileName": filename,
            "Hash": calculate_hash(filename)  # Calculate hash of the filename string
        }

        # Add SkipRegions if present
        skip_regions = load_skip_regions(filename)
        if skip_regions:
            file_info["SkipRegions"] = skip_regions

        manifest["Files"].append(file_info)

    return manifest

def create_tar(output_file, manifest_path, sig_file):
    """Create the tar file with MANIFEST.json and optionally MANIFEST.json.sig."""
    output_dir = Path("../output")  # Set the output folder path
    output_file_path = output_dir / output_file  # Join folder path with the tar file name

    with tarfile.open(output_file_path, "w") as tar:
        tar.add(manifest_path, arcname="MANIFEST.json")
        tar.add(sig_file, arcname="MANIFEST.json.sig")

        
def clean_up_files():
    """Cleanup: remove MANIFEST.json and MANIFEST.sig if they exist."""
    if os.path.exists("MANIFEST.json"):
        os.remove("MANIFEST.json")
    if os.path.exists("MANIFEST.sig"):
        os.remove("MANIFEST.sig")



def main():
    parser = argparse.ArgumentParser(description="Generate Firmware Tarball with Manifest and Signing.")
    parser.add_argument("-j", "--json-format", action="store_true", required=True, help="Generate manifest in JSON format")
    parser.add_argument("-s", "--sign", action="store_true", required=True, help="Sign the manifest using default private key")
    parser.add_argument("-o", "--out", required=True, help="Output tarball name")
    parser.add_argument("-m", "--machine", required=True, help="Target machine name")
    parser.add_argument("-c", "--compatible", required=True, help="Compatible name for image")
    parser.add_argument("-v", "--version", required=True, help="Version of the image")
    parser.add_argument("-e", "--extended_version", required=True, help="Extended version of the image")
    parser.add_argument("filenames", nargs="+", help="Firmware filenames (e.g. yyy.0.BS.1B09.GN.1.7z zzz.0.BS.1B09.GN.1.7z)")

    args = parser.parse_args()

    # Create the manifest
    manifest = create_json_manifest(args.machine, args.compatible, args.version, args.extended_version, args.filenames)

    # Write manifest to JSON file
    manifest_path = Path("MANIFEST.json")
    with open(manifest_path, 'w') as mf:
        json.dump(manifest, mf, indent=4)

    private_key_file = "../key/customkey"  # Update the path to the private key

    # Sign the manifest
    sig_file = sign_manifest(private_key_file, manifest_path)

    # Create the final tarball
    create_tar(args.out, manifest_path, sig_file)

    # Clean up temporary files
    clean_up_files()

    print(f"Created tarball {args.out} with MANIFEST.json" + (f" and MANIFEST.json.sig" if args.sign else ""))

if __name__ == "__main__":
    main()
