#!/usr/bin/env python3
"""Compare end-to-end NASFS and OpenSSH SFTP on a dedicated Linux NAS."""

import argparse
import csv
import hashlib
import math
import os
from pathlib import Path
import re
import secrets
import shlex
import statistics
import subprocess
import tempfile
import time


SFTP_PROFILES = (
    ("chacha20-poly1305@openssh.com", None),
    ("aes128-gcm@openssh.com", None),
    ("aes256-gcm@openssh.com", None),
    ("aes256-ctr", "hmac-sha2-256-etm@openssh.com"),
)


def command(args, *, env=None, stdin=None):
    result = subprocess.run(args, env=env, input=stdin, text=True,
                            capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError(f"{Path(args[0]).name} failed: {result.stderr.strip()}")
    return result


def same_bytes(first, second):
    def digest(path):
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").digest()
    if first.stat().st_size != second.stat().st_size or digest(first) != digest(second):
        raise RuntimeError("Transferred content does not match the input")


def sftp_path(path):
    return '"' + str(path).replace("\\", "\\\\").replace('"', '\\"') + '"'


def cpu_usage(options, target, port, counter):
    result = command(["ssh", *options, "-p", str(port), "--", target,
                      "cat -- " + shlex.quote(counter)])
    matches = re.findall(r"^usage_usec (\d+)$", result.stdout, re.M)
    if len(matches) != 1:
        raise RuntimeError("Expected cgroup v2 usage_usec counter")
    return int(matches[0])


def measure(transfer, counter, size):
    before = counter()
    start = time.monotonic_ns()
    result = transfer()
    seconds = (time.monotonic_ns() - start) / 1e9
    cpu_seconds = (counter() - before) / 1e6
    if cpu_seconds < 0:
        raise RuntimeError("The NAS CPU counter reset during the transfer")
    return {
        "seconds": seconds,
        "mib_per_second": size / (1024 ** 2 * seconds),
        "nas_cpu_seconds_per_gib": cpu_seconds * 1024 ** 3 / size,
    }, result


def write_samples(output, samples):
    with output.open("w", newline="") as file:
        writer = csv.DictWriter(file, samples[0].keys())
        writer.writeheader()
        writer.writerows(samples)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--nasfs-ip", required=True, help="NASFS IPv4 address")
    parser.add_argument("--nasfs-port", type=int, default=5252)
    parser.add_argument("--management", required=True, help="SSH login on the NAS")
    parser.add_argument("--management-port", type=int, required=True)
    parser.add_argument("--sftp", help="SFTP test service login on the same NAS")
    parser.add_argument("--sftp-port", type=int, default=22)
    parser.add_argument("--known-hosts", type=Path, required=True)
    parser.add_argument("--nasfs-cpu", required=True, help="NASFS cgroup cpu.stat")
    parser.add_argument("--sftp-cpu", help="Dedicated SFTP service cgroup cpu.stat")
    parser.add_argument("--series", choices=["baseline", "resume", "ecc"],
                        default="baseline")
    parser.add_argument("--ecc", choices=["xor-4+1", "xor-8+1", "xor-16+1", "rs-8+2"],
                        default="rs-8+2")
    parser.add_argument("--sizes", type=int, nargs="+",
                        default=[4096, 65536, 1048576, 16777216, 134217728])
    parser.add_argument("--runs", type=int, default=20)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.runs < 1 or any(size < 1 for size in args.sizes):
        parser.error("Runs and sizes must be positive")
    if args.series == "baseline" and (not args.sftp or not args.sftp_cpu):
        parser.error("The baseline requires a dedicated SFTP service and CPU counter")
    if args.sftp and args.sftp == args.management and args.sftp_port == args.management_port:
        parser.error("Use a separate SSH service for CPU counter queries")
    return args


def main():
    args = parse_args()
    ssh_options = [
        "-oBatchMode=yes", "-oStrictHostKeyChecking=yes", "-oConnectTimeout=10",
        "-oServerAliveInterval=10", "-oServerAliveCountMax=3",
        f"-oUserKnownHostsFile={args.known_hosts.resolve()}",
    ]
    environment = dict(os.environ, NASFS_SERVER_IP=args.nasfs_ip,
                       NASFS_SERVER_PORT=str(args.nasfs_port),
                       NASFS_ECC=args.ecc if args.series == "ecc" else "off")
    environment.pop("NASFS_EXPECTED_MANIFEST", None)
    client = str(args.client.resolve())
    remote = "/tmp/nasfs-bench-" + secrets.token_hex(16)
    batch = ["sftp", *ssh_options, "-P", str(args.sftp_port), "-b", "-"]
    samples = []

    def cpu(path):
        return cpu_usage(ssh_options, args.management, args.management_port, path)

    def sftp(lines, cipher=None, mac=None):
        algorithms = [] if cipher is None else ["-v", "-c", cipher]
        if mac:
            algorithms += ["-oMACs=" + mac]
        return command([*batch, *algorithms, "--", args.sftp], stdin=lines)

    def record(tool, profile, size, run, direction, metrics, algorithms=""):
        samples.append(dict(series=args.series, tool=tool, profile=profile, bytes=size,
                            run=run, direction=direction, algorithms=algorithms,
                            **metrics))

    def measure_nasfs(size, run, source, output, directory):
        name = f"benchmark-{remote.split('-')[-1]}-{size}-{run}"
        put = ["put", str(source), name]
        if args.series == "resume":
            put = ["put-resume", str(directory / "put.journal"), str(source), name]
        def nasfs(argv, env=environment):
            return command([client, *argv], env=env)

        metrics, result = measure(lambda: nasfs(put), lambda: cpu(args.nasfs_cpu), size)
        published = re.search(r"^Upload published. Manifest digest: ([0-9a-f]{64})$",
                              result.stdout, re.M)
        if not published:
            raise RuntimeError("NASFS PUT did not return a manifest digest")
        digest = published[1]
        profile = environment["NASFS_ECC"] if args.series == "ecc" else args.series
        record("nasfs", profile, size, run, "put", metrics,
               "xchacha20poly1305 secretstream")
        get = ["get", name, str(output)]
        if args.series == "resume":
            resolved = nasfs(["resolve", name]).stdout
            version = re.search(r"^([0-9a-f]{32}) " + digest + "$", resolved, re.M)
            if not version:
                raise RuntimeError("NASFS resolved a different version")
            object_id = version[1]
            get = ["get-resume", str(directory / "get.journal"), object_id, digest, str(output)]
        checked_env = dict(environment, NASFS_EXPECTED_MANIFEST=digest)
        metrics, _ = measure(lambda: nasfs(get, checked_env), lambda: cpu(args.nasfs_cpu), size)
        same_bytes(source, output)
        record("nasfs", profile, size, run, "get", metrics,
               "xchacha20poly1305 secretstream")

    def measure_sftp(size, run, source, output):
        for cipher, mac in SFTP_PROFILES:
            upload = (f"put -f {sftp_path(source)} {remote}/partial\n"
                      f"rename {remote}/partial {remote}/data\n")
            download = f"get {remote}/data {sftp_path(output)}\n"
            for direction, lines in (("put", upload), ("get", download)):
                metrics, result = measure(lambda: sftp(lines, cipher, mac),
                                          lambda: cpu(args.sftp_cpu), size)
                negotiated = re.findall(r"kex: (.+? cipher: .+)", result.stderr)
                if len(negotiated) != 2 or any(f"cipher: {cipher} " not in line
                                                for line in negotiated):
                    raise RuntimeError("OpenSSH negotiated an unexpected cipher")
                if mac and any(f"MAC: {mac} " not in line for line in negotiated):
                    raise RuntimeError("OpenSSH negotiated an unexpected MAC")
                record("sftp", cipher, size, run, direction, metrics, " | ".join(negotiated))
            same_bytes(source, output)
            sftp(f"rm {remote}/data\n")

    compare = args.series == "baseline"
    if compare:
        sftp(f"mkdir {remote}\n")
    try:
        for size in args.sizes:
            with tempfile.TemporaryDirectory(prefix="nasfs-benchmark-") as root:
                directory = Path(root)
                source, cipher_input, output = (directory / name for name in
                                                ("source", "ciphertext", "output"))
                with source.open("wb") as stream:
                    for offset in range(0, size, 1048576):
                        stream.write(os.urandom(min(1048576, size - offset)))
                if compare:
                    command(["openssl", "enc", "-aes-256-ctr", "-nosalt",
                             "-K", secrets.token_hex(32), "-iv", secrets.token_hex(16),
                             "-in", str(source), "-out", str(cipher_input)])
                for run in range(1, args.runs + 1):
                    measure_nasfs(size, run, source, output, directory)
                    if compare:
                        measure_sftp(size, run, cipher_input, output)
                    for journal in (directory / "put.journal", directory / "get.journal"):
                        journal.unlink(missing_ok=True)
    finally:
        try:
            if compare:
                sftp(f"-rm {remote}/partial\n-rm {remote}/data\nrmdir {remote}\n")
        finally:
            if samples:
                write_samples(args.output, samples)

    groups = {}
    for row in samples:
        key = tuple(row[field] for field in ("tool", "profile", "bytes", "direction"))
        groups.setdefault(key, []).append(row)

    summary = []
    for (tool, profile, size, direction), rows in groups.items():
        times = sorted(row["seconds"] for row in rows)
        summary.append(dict(tool=tool, profile=profile, bytes=size, direction=direction,
                            runs=len(rows), p95_seconds=times[math.ceil(len(times) * .95) - 1],
                            median_mib_per_second=statistics.median(
                                row["mib_per_second"] for row in rows),
                            median_nas_cpu_seconds_per_gib=statistics.median(
                                row["nas_cpu_seconds_per_gib"] for row in rows)))
    write_samples(args.output.with_suffix(".summary.csv"), summary)


if __name__ == "__main__":
    main()
