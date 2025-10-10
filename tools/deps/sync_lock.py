import tomllib
import tomli_w
from collections import defaultdict
import shutil


def load_lock(path):
    with open(path, "rb") as f:
        return tomllib.load(f)


def overwrite_lock(lock_a_path: str, lock_b_path: str, ignore: set, replace: dict):
    lock_a = load_lock(lock_a_path)
    lock_b = load_lock(lock_b_path)

    a_map = {pkg["name"]: pkg for pkg in lock_a["package"]}

    # Group packages in B by name to detect multiple versions
    b_name_map = defaultdict(list)
    for pkg in lock_b["package"]:
        b_name_map[pkg["name"]].append(pkg)

    # overwrite packages in B with those in A
    for name, pkgs in b_name_map.items():
        if name in ignore:
            print(f"{name} is in ignore list, skipping...")
            continue

        if len(pkgs) > 1:
            print(f"{name} has multiple versions in B, skipping...")
            continue

        # overwrite attributes
        b_pkg = pkgs[0]
        if name in a_map:
            a_pkg = a_map[name]

            if b_pkg.get("version") == a_pkg.get("version"):
                continue

            print(f"Crate overwritten: {name}, version : {b_pkg.get('version')} -> {a_pkg.get('version')}")

            for key in ["version", "source", "checksum"]:
                if key in a_pkg:
                    b_pkg[key] = a_pkg[key]

            if "dependencies" in a_pkg:
                b_pkg["dependencies"] = a_pkg["dependencies"]
            else:
                b_pkg.pop("dependencies", None)

    # Write to temporary file first
    tmp_path = lock_b_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(tomli_w.dumps(lock_b))

    # Replace indent to avoid finding diff in Cargo.lock
    with open(tmp_path, "r+", encoding="utf-8") as f:
        content = f.read()
        # formatting
        content = content.replace("    ", " ")
        for old, new in replace.items():
            content = content.replace(old, new)
        f.seek(0)
        f.write(content)
        f.truncate()

    shutil.move(tmp_path, lock_b_path)
    print(f"Patched Cargo.lock written and moved to {lock_b_path}")


if __name__ == "__main__":
    # Paths are relative to this script
    lock_kona = "../../../../op-rs/kona/Cargo.lock"
    lock_self = "../../Cargo.lock"

    ignore = [
        # We must use patched time version
        "time",
    ]
    overwrite_lock(lock_kona, lock_self, set(ignore), {})
