#!/usr/bin/env python3

import os
import time
import hashlib
import json
import logging
import argparse

import requests

RETRY_SLEEP = 30
RETRY_COUNT = 10
WRITE_ERROR_TXT = True
REQUESTS_PER_DECOMPILER = 3
USE_DECOMPILER_NAME_MAP = True
CPP_FILE_EXTENSION = "cpp"

DECOMPILER_NAMES = {
    "BinaryNinja": "binary-ninja",
    "Boomerang": "boomerang",
    "Ghidra": "ghidra",
    "Hex-Rays": "hex-rays",
    "RecStudio": "recstudio",
    "Reko": "reko",
    "Relyze": "relyze",
    "RetDec": "retdec",
    "Snowman": "snowman",
}

CACHE_DIR = os.path.expanduser("~/.cache/dogbolt/")


def log(msg):
    logging.info(msg)


def maybe_upload_binary(file_path):
    log(f"binary path: {file_path}")

    file_size = os.path.getsize(file_path)
    log(f"binary size: {file_size}")
    if file_size > 2 * 1024 * 1024:
        log("error: binary is too large. binary must be smaller than 2 MB")
        exit(1)

    def compute_sha256(file_path):
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()

    file_sha256 = compute_sha256(file_path)
    log(f"binary hash: sha256:{file_sha256}")

    binary_id_cache_path = os.path.join(CACHE_DIR, "binary_id.txt")
    os.path.join(CACHE_DIR, "result_hash.txt")
    os.makedirs(CACHE_DIR, exist_ok=True)

    binary_id = ""
    if os.path.exists(binary_id_cache_path):
        with open(binary_id_cache_path, "r") as f:
            for line in f:
                if line.startswith(f"sha256:{file_sha256} "):
                    binary_id = line.strip().split(" ")[1]
                    break

    if not binary_id:
        log("Uploading binary...")
        response = requests.post(
            "https://dogbolt.org/api/binaries/",
            files={"file": open(file_path, "rb")},
        )
        binary_id = response.json().get("id")
        with open(binary_id_cache_path, "a") as f:
            f.write(f"sha256:{file_sha256} {binary_id}\n")

    log(f"binary id: {binary_id}")
    return binary_id


def download_result(
    result,
    file_path,
    done_decompiler_keys,
    request_count_by_decompiler_key,
    binary_id,
):
    decompiler_name = result["decompiler"]["name"]
    decompiler_version = result["decompiler"]["version"]
    decompiler_key = f"{decompiler_name}-{decompiler_version}"

    if decompiler_key in done_decompiler_keys:
        return

    if USE_DECOMPILER_NAME_MAP and decompiler_name in DECOMPILER_NAMES:
        decompiler_name = DECOMPILER_NAMES[decompiler_name]

    output_extension = (
        "c" if decompiler_name != "snowman" else CPP_FILE_EXTENSION
    )
    output_path = os.path.join(
        os.path.dirname(file_path),
        "src",
        f"{decompiler_name}-{decompiler_version}",
        f"{os.path.basename(file_path).rsplit('.', 1)[0]}.{output_extension}",
    )
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    error = result.get("error")
    if error == "Exceeded time limit":
        if (
            request_count_by_decompiler_key.get(decompiler_key, 0)
            >= REQUESTS_PER_DECOMPILER
        ):
            log(f"error: timeout from decompiler {decompiler_key}")
            return
        request_count_by_decompiler_key[decompiler_key] = (
            request_count_by_decompiler_key.get(decompiler_key, 0) + 1
        )
        log(
            f"error: timeout from decompiler {decompiler_key} - retrying "
            f"(done {request_count_by_decompiler_key[decompiler_key]} of "
            f"{REQUESTS_PER_DECOMPILER} requests)"
        )
        requests.post(
            f"https://dogbolt.org/api/binaries/{binary_id}/"
            f"decompilations/{result['id']}/rerun/"
        )
        return
    elif error:
        log(f"error: {decompiler_name}-{decompiler_version}")
        if WRITE_ERROR_TXT:
            with open(
                os.path.join(os.path.dirname(output_path), "error.txt"),
                "w",
            ) as f:
                f.write(error)
        done_decompiler_keys.add(decompiler_key)
        return

    download_url = result["download_url"]
    log(f"writing {output_path}")
    with open(output_path, "wb") as f:
        f.write(requests.get(download_url).content)

    done_decompiler_keys.add(decompiler_key)


def dogbolt_decompile(file_path):
    if not file_path or not os.path.isfile(file_path):
        log("Error: Please provide a valid path to the file")
        exit(1)

    binary_id = maybe_upload_binary(file_path)

    log("fetching decompiler names")
    response = requests.get("https://dogbolt.org/")
    decompilers_json = json.loads(
        response.text.split(
            '<script id="decompilers_json" type="application/json">'
        )[1].split("</script>")[0]
    )
    decompilers_names = list(decompilers_json.keys())
    decompilers_count = len(decompilers_names)
    log(f"decompiler names: {', '.join(decompilers_names)}")

    done_decompiler_keys = set()
    request_count_by_decompiler_key = {}

    for _retry_step in range(RETRY_COUNT):
        log("fetching results...")
        response = requests.get(
            f"https://dogbolt.org/api/binaries/{binary_id}/"
            "decompilations/?completed=true"
        )
        status_json = response.json()
        status_json["count"]

        for result in status_json["results"]:
            download_result(
                result,
                file_path,
                done_decompiler_keys,
                request_count_by_decompiler_key,
                binary_id,
            )

        if len(done_decompiler_keys) == decompilers_count:
            log("fetched all results")
            break

        log(
            f"fetched {len(done_decompiler_keys)} of {decompilers_count}"
            f" results. retrying in {RETRY_SLEEP} seconds"
        )
        time.sleep(RETRY_SLEEP)

    log("The process is complete.")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--file-path", type=str, help="Path to the file", required=True
    )
    return parser.parse_args().__dict__


def main():
    logging.basicConfig(level=logging.INFO)
    dogbolt_decompile(**parse_args())

if __name__ == "__main__":
    main()
