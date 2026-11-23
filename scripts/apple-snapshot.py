"""Read transport-policy declarations from a supplied built app's Info.plist."""
import argparse
import json
from pathlib import Path
import plistlib

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("plist", type=Path)
args = parser.parse_args()
with args.plist.open("rb") as stream:
    manifest = plistlib.load(stream)
policy = manifest.get("NSAppTransportSecurity", {})
if not isinstance(policy, dict) or not manifest.get("CFBundleIdentifier"):
    parser.error("Expected an application Info.plist")
print(json.dumps({
    "bundle": manifest["CFBundleIdentifier"],
    "build": str(manifest.get("CFBundleVersion", "")),
    "allowsArbitraryLoads": policy.get("NSAllowsArbitraryLoads"),
    "exceptionDomains": list(policy.get("NSExceptionDomains", {})),
}))
