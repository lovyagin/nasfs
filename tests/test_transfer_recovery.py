"""Interrupt real CLI transfers at frame boundaries using a loopback relay."""

from contextlib import suppress
import os
from pathlib import Path
import signal
import shutil
import socket
import subprocess
import sys
import threading
import time

SERVER_SELECTION = 0x02
KEM_CIPHERTEXT = 0x03
HELLO = 0x05
READY = 0x06
AUTH = 0x10
AUTH_ACK = 0x11
PUT_REQ = 0x12
GET_REQ = 0x15
PAKE_HELLO = 0x1A
PAKE_RESPONSE = 0x1B
PUT_ACK = 0x13
PUT_DONE = 0x14
GET_ACK = 0x16
GET_DONE = 0x17
PUT_RESULT = 0x1C
PUT_DATA = 0x20
GET_DATA = 0x21


def read_exact(sock, size):
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            return None
        result.extend(chunk)
    return result


def relay(source, target, stop_at, reached, stop, observed, corrupt, occurrence,
          before_forward, slow_frame_seconds, stall_partial):
    try:
        while not stop.is_set():
            prefix = read_exact(source, 4)
            if prefix is None:
                break
            frame = read_exact(source, int.from_bytes(prefix, "big"))
            if frame is None:
                break
            if observed is not None:
                observed.append(frame[0])
            if frame[0] == stop_at:
                occurrence -= 1
            selected = frame[0] == stop_at and occurrence == 0
            if selected:
                if slow_frame_seconds:
                    target.sendall(prefix)
                    for index in range(8):
                        start = len(frame) * index // 8
                        end = len(frame) * (index + 1) // 8
                        target.sendall(frame[start:end])
                        if index != 7 and stop.wait(slow_frame_seconds / 7):
                            return
                    reached.set()
                    continue
                if stall_partial:
                    target.sendall(prefix + frame[:1])
                    reached.set()
                    stop.wait()
                    break
                if before_forward is not None:
                    before_forward()
                elif corrupt:
                    frame[-1] ^= 1
                else:
                    reached.set()
                    stop.wait()
                    break
            target.sendall(prefix + frame)
            if selected:
                reached.set()
    except OSError:
        pass
    finally:
        with suppress(OSError):
            target.shutdown(socket.SHUT_WR)


def interrupt_transfer(client, args, upstream_port, direction, command, sig,
                       server_pid=None, corrupt=False, occurrence=1, cwd=None,
                       before_forward=None, on_pause=None, forbid=(),
                       wait_for_remote_close=False, auth_method=None,
                       slow_frame_seconds=0, stall_partial=False):
    observed = []
    reached = threading.Event()
    stop = threading.Event()
    workers = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(10)
        relay_port = listener.getsockname()[1]
        env = dict(os.environ, NASFS_SERVER_PORT=str(relay_port))
        if auth_method is not None:
            env["NASFS_AUTH_METHOD"] = auth_method
        trust = Path(env["HOME"]) / ".nasfs"
        shutil.copy(trust / f"server-127.0.0.1-{upstream_port}.pub",
                        trust / f"server-127.0.0.1-{relay_port}.pub")
        with subprocess.Popen(
            [client, *args], env=env, cwd=cwd, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE
        ) as child:
            try:
                with listener.accept()[0] as peer, socket.create_connection(
                    ("127.0.0.1", upstream_port), timeout=10
                ) as upstream:
                    for connection in (peer, upstream):
                        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        if slow_frame_seconds:
                            connection.settimeout(slow_frame_seconds + 15)
                    for label, source, target in (
                        ("put", peer, upstream),
                        ("get", upstream, peer),
                    ):
                        worker = threading.Thread(
                            target=relay,
                            args=(source, target, command if label == direction else None,
                                  reached, stop, observed if label == "put" else None,
                                  corrupt, occurrence, before_forward,
                                  slow_frame_seconds, stall_partial),
                        )
                        workers.append(worker)
                        worker.start()
                    try:
                        if not reached.wait(10 + slow_frame_seconds):
                            raise RuntimeError(f"Did not reach command {command:#x}")
                        if on_pause is not None:
                            on_pause()
                        if corrupt or before_forward is not None or wait_for_remote_close or slow_frame_seconds:
                            pass
                        elif server_pid is not None:
                            os.kill(server_pid, sig)
                            if direction == "get":
                                # The relay is holding a server frame and
                                # cannot forward EOF from that socket.
                                peer.shutdown(socket.SHUT_RDWR)
                        elif sig is None:
                            peer.shutdown(socket.SHUT_RDWR)
                        else:
                            child.send_signal(sig)
                        _, stderr = child.communicate(timeout=5)
                        expected_status = 1 if server_pid or sig is None else 128 + sig
                        if slow_frame_seconds:
                            expected_status = 0
                        if sig == signal.SIGKILL and server_pid is None:
                            expected_status = -signal.SIGKILL
                        assert child.returncode == expected_status, stderr.decode()
                        if sig is not None and sig != signal.SIGKILL and server_pid is None:
                            assert b"Transfer interrupted by signal" in stderr, stderr
                        disallowed = (*forbid, AUTH, PAKE_HELLO) if corrupt else forbid
                        assert not set(disallowed).intersection(observed), observed
                        return stderr
                    finally:
                        stop.set()
                        with suppress(OSError):
                            peer.shutdown(socket.SHUT_RDWR)
                        with suppress(OSError):
                            upstream.shutdown(socket.SHUT_RDWR)
            finally:
                if child.poll() is None:
                    child.kill()
                for worker in workers:
                    worker.join()


def await_cleanup(directory, pattern):
    deadline = time.monotonic() + 5
    while list(directory.glob(pattern)):
        if time.monotonic() >= deadline:
            raise RuntimeError(f"Temporary files left in {directory}: {pattern}")
        time.sleep(0.02)


def main():
    client, root, storage, source, server_pid, *mode = sys.argv[1:]
    client = str(Path(client).resolve())
    root, storage, source = Path(root), Path(storage), Path(source)
    staging = storage / ".nasfs"
    upstream_port = int(os.environ["NASFS_SERVER_PORT"])
    remote = "encrypted_remote.bin"
    destination = root / "interrupted.bin"
    replacement = root / "replacement.bin"
    replacement.write_bytes(b"Replacement from the interrupted transfer\n")
    previous = (storage / remote).read_bytes()
    put = ["put", str(replacement), remote]
    get = ["get", remote, str(destination)]

    def verify_second_connection():
        output = root / "parallel-get.bin"
        subprocess.run([client, "get", "concurrent-a.bin", str(output)],
                       check=True, capture_output=True, timeout=5)
        assert output.read_bytes() == source.read_bytes()

    if mode:
        if mode == ["partial-put"]:
            slow_remote = "slow-frame.bin"
            slow_put = ["put", str(replacement), slow_remote]
            interrupt_transfer(client, slow_put, upstream_port, "put", PUT_DATA, None,
                               slow_frame_seconds=3.5)
            stored = storage / slow_remote
            before = stored.read_bytes()
            interrupt_transfer(client, slow_put, upstream_port, "put", PUT_DATA, None,
                               wait_for_remote_close=True, stall_partial=True)
            assert stored.read_bytes() == before
            assert "Session idle timeout." in (root / "logs/server.log").read_text()
            await_cleanup(staging, ".nasfs-upload.*")
            return
        if mode == ["partial-get"]:
            slow_get = ["get", "slow-frame.bin", str(destination)]
            interrupt_transfer(client, slow_get, upstream_port, "get", GET_DATA, None,
                               slow_frame_seconds=32)
            assert destination.read_bytes() == replacement.read_bytes()
            return
        if mode[0] in ("stop-during-publication", "publication-without-lock"):
            unlocked = mode == ["publication-without-lock"]
            orphan = staging / (".nasfs-upload." + "0" * 32)
            server_pid = int(server_pid)
            output_log = root / "logs/server_stdout.log"
            gate = root / "release-rename"
            with subprocess.Popen([client, *put], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE) as child:
                try:
                    deadline = time.monotonic() + 8
                    while "Test fixture blocked upload rename" not in output_log.read_text():
                        assert child.poll() is None
                        assert time.monotonic() < deadline, output_log.read_text()
                        time.sleep(0.01)
                    assert (storage / remote).read_bytes() == previous
                    uploads = set(staging.glob(".nasfs-upload.*"))
                    if unlocked:
                        assert orphan in uploads
                        uploads.remove(orphan)
                    assert len(uploads) == 1, uploads
                    active = uploads.pop()
                    assert active.name.startswith(".nasfs-upload.unlocked.") == unlocked
                    verify_second_connection()
                    # A second server starting on this directory must leave
                    # the first server's in-flight staging file intact.
                    peer_log = root / "logs/peer.log"
                    peer_log.unlink(missing_ok=True)
                    peer_config = root / "peer.conf"
                    config = (root / "server-restarted.conf").read_text()
                    config = config.replace(str(root / "logs/server.log"), str(peer_log))
                    config = config.replace(str(root / "logs/server.pid"),
                                            str(root / "logs/peer.pid"))
                    peer_config.write_text(config)
                    server = os.environ["NASFS_RECOVERY_PEER_SERVER"]
                    with subprocess.Popen([server, peer_config],
                                          stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL) as peer:
                        try:
                            deadline = time.monotonic() + 5
                            while not peer_log.exists() or "listening on" not in peer_log.read_text():
                                assert peer.poll() is None
                                assert time.monotonic() < deadline
                                time.sleep(0.01)
                            assert set(staging.glob(".nasfs-upload.*")) == {active}
                        finally:
                            if peer.poll() is None:
                                peer.terminate()
                            peer.wait(timeout=5)
                    assert peer.returncode == 0, peer_log.read_text()
                    os.kill(server_pid, signal.SIGTERM)
                    gate.touch()
                    stdout, stderr = child.communicate(timeout=5)
                    if child.returncode == 0:
                        assert b"Upload published." in stdout, stdout
                    else:
                        assert child.returncode == 1, stderr
                        assert b"PUT outcome unknown" in stderr, stderr
                finally:
                    gate.touch()
                    if child.poll() is None:
                        child.kill()
            await_cleanup(staging, ".nasfs-upload.*")
            assert (storage / remote).read_bytes() != previous
            return
        if mode == ["cancel-slow-mput"]:
            items = [root / f"slow-put-{index}.bin" for index in range(3)]
            items[0].touch()
            items[1].write_bytes(source.read_bytes()[:65536])
            items[2].write_bytes(b"Must not be transferred")
            output_log = root / "logs/server_stdout.log"
            gate = root / "release-writes"

            def await_saturated_queue():
                deadline = time.monotonic() + 5
                while "Test fixture pending writes: 4" not in output_log.read_text():
                    assert time.monotonic() < deadline, output_log.read_text()
                    time.sleep(0.01)

            try:
                interrupt_transfer(client, ["mput", *map(str, items)], upstream_port,
                                   "put", PUT_DONE, signal.SIGINT, occurrence=2,
                                   on_pause=await_saturated_queue)
            finally:
                gate.touch()
            await_cleanup(staging, ".nasfs-upload.*")
            subprocess.run([client, "get", items[0].name, str(destination)],
                           check=True, capture_output=True, timeout=10)
            assert destination.read_bytes() == b""
            assert not any((storage / item.name).exists() for item in items[1:])
            return

        if mode == ["cancel-slow-mget"]:
            output = root / "slow-get-output"
            output.mkdir()
            names = [f"slow-get-{index}.bin" for index in range(3)]
            for name in names:
                (output / name).write_bytes(b"Previous destination")
            output_log = root / "logs/server_stdout.log"
            gate = root / "release-read"
            with subprocess.Popen([client, "mget", *names], cwd=output,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE) as child:
                try:
                    deadline = time.monotonic() + 8
                    while "Test fixture blocked record read" not in output_log.read_text():
                        assert child.poll() is None and time.monotonic() < deadline
                        time.sleep(0.01)
                    child.send_signal(signal.SIGINT)
                    _, stderr = child.communicate(timeout=5)
                    assert child.returncode == 130, stderr
                    assert b"Transfer interrupted by signal" in stderr, stderr
                finally:
                    gate.touch()
                    if child.poll() is None:
                        child.kill()
            assert (output / names[0]).read_bytes() == source.read_bytes()
            for name in names[1:]:
                assert (output / name).read_bytes() == b"Previous destination"
            await_cleanup(output, ".nasfs-download.*")
            return
        stop_prefix = "stop-during-"
        opening_io = mode[0][len(stop_prefix):] if mode[0].startswith(stop_prefix) else ""
        header_phases = ("put-header", "get-header", "get-slot")
        if mode == ["disconnect-put-header"] or opening_io in (
            "open", "read", "prefix", *header_phases
        ):
            disconnecting = mode == ["disconnect-put-header"]
            if disconnecting:
                opening_io = "put-header"
            reading = opening_io not in ("open", "put-header")
            server_pid = int(server_pid)
            output_log = root / "logs/server_stdout.log"
            gate = root / ("release-read" if reading else "release-open")
            marker = "blocked record read" if reading else "blocked upload open"
            if opening_io in header_phases:
                gate = root / "release-open-io"
                marker = f"blocked {opening_io}"
            if reading:
                destination.write_bytes(b"Previous destination")
            with subprocess.Popen([client, *(get if reading else put)], stdout=subprocess.DEVNULL,
                                  stderr=subprocess.PIPE) as child:
                try:
                    deadline = time.monotonic() + 8
                    while marker not in output_log.read_text():
                        assert child.poll() is None
                        assert time.monotonic() < deadline, output_log.read_text()
                        time.sleep(0.01)
                    if opening_io == "prefix" or opening_io in header_phases:
                        verify_second_connection()
                    if disconnecting:
                        child.kill()
                        child.wait(timeout=5)
                    else:
                        os.kill(server_pid, signal.SIGTERM)
                        _, stderr = child.communicate(timeout=5)
                        assert child.returncode == 1, stderr
                        assert b"PUT outcome unknown" not in stderr, stderr
                        assert "shutting down cleanly" in (root / "logs/server.log").read_text()
                        os.kill(server_pid, 0)
                finally:
                    gate.touch()
                    if child.poll() is None:
                        child.kill()
            if disconnecting:
                await_cleanup(staging, ".nasfs-upload.*")
            assert (storage / remote).read_bytes() == previous
            if reading:
                assert destination.read_bytes() == b"Previous destination"
                assert not list(root.glob(".nasfs-download.*"))
            return
        if mode in (["cancel-full-queue"], ["stop-full-queue"], ["timeout-full-queue"]):
            stop_server = mode == ["stop-full-queue"]
            wait_for_timeout = mode == ["timeout-full-queue"]
            block_workers = stop_server or wait_for_timeout
            queue_log = root / "logs/server_stdout.log"
            gate = root / ("release-blocked-writes" if block_workers else "release-writes")
            replacement.write_bytes(source.read_bytes()[:65536])
            marker = ("Test fixture blocked writes: 4" if block_workers
                      else "Test fixture pending writes: 4")

            def await_full_queue():
                deadline = time.monotonic() + 5
                while marker not in queue_log.read_text():
                    assert time.monotonic() < deadline, queue_log.read_text()
                    time.sleep(0.01)

            try:
                signum = None if wait_for_timeout else (signal.SIGTERM if stop_server else signal.SIGINT)
                stderr = interrupt_transfer(
                    client, put, upstream_port, "put", PUT_DONE, signum,
                    int(server_pid) if stop_server else None, on_pause=await_full_queue,
                    wait_for_remote_close=wait_for_timeout,
                )
                if block_workers:
                    assert b"PUT outcome unknown" in stderr, stderr
                    expected_log = "Session idle timeout." if wait_for_timeout else "shutting down cleanly"
                    assert expected_log in (root / "logs/server.log").read_text()
                    os.kill(int(server_pid), 0)
            finally:
                gate.touch()
            await_cleanup(staging, ".nasfs-upload.*")
            assert (storage / remote).read_bytes() == previous
            return
        before_publication = mode == ["crash-before"]
        assert before_publication or mode == ["crash-after"], mode
        direction, command = ("put", PUT_DONE) if before_publication else ("get", PUT_RESULT)
        stderr = interrupt_transfer(client, put, upstream_port, direction, command,
                                    signal.SIGKILL, int(server_pid))
        assert b"PUT outcome unknown" in stderr, stderr
        temporary = list(staging.glob(".nasfs-upload.*"))
        if before_publication:
            assert (storage / remote).read_bytes() == previous
            assert len(temporary) == 1, temporary
            assert temporary[0].is_file()
        else:
            assert (storage / remote).read_bytes() != previous
            assert not temporary, temporary
        return

    for direction, command in (
        ("put", HELLO), ("get", SERVER_SELECTION),
        ("put", KEM_CIPHERTEXT), ("get", READY),
    ):
        interrupt_transfer(client, get, upstream_port, direction, command, None,
                           forbid=(AUTH, PAKE_HELLO, PUT_REQ, GET_REQ))
        assert not destination.exists()
    interrupt_transfer(client, get, upstream_port, "get", AUTH_ACK, None,
                       forbid=(PUT_REQ, GET_REQ))
    assert not destination.exists()

    for direction, command in (
        ("put", PAKE_HELLO), ("get", PAKE_RESPONSE),
        ("put", AUTH), ("get", AUTH_ACK),
    ):
        forbid = (PUT_REQ, GET_REQ)
        if command in (PAKE_HELLO, PAKE_RESPONSE):
            forbid += (AUTH,)
        interrupt_transfer(client, get, upstream_port, direction, command, None,
                           forbid=forbid, auth_method="pake")
        assert not destination.exists()

    for cmd, expected in (
        (SERVER_SELECTION, b"Server identity verification failed"),
        (READY, b"Server handshake confirmation failed"),
    ):
        stderr = interrupt_transfer(client, get, upstream_port, "get", cmd,
                                    None, corrupt=True)
        assert expected in stderr, stderr
        assert not destination.exists()

    for direction, command in (
        ("get", PUT_ACK), ("put", PUT_DATA), ("put", PUT_DONE),
    ):
        interrupt_transfer(client, put, upstream_port, direction, command,
                           signal.SIGINT)
        await_cleanup(staging, ".nasfs-upload.*")
        assert (storage / remote).read_bytes() == previous

    shrinking_source = root / "shrinking-source.bin"
    shrinking_source.write_bytes(source.read_bytes())
    stderr = interrupt_transfer(client, ["put", str(shrinking_source), remote],
                                upstream_port, "get", PUT_ACK, None,
                                before_forward=lambda: shrinking_source.write_bytes(b""))
    assert b"PUT source size changed during upload" in stderr, stderr
    await_cleanup(staging, ".nasfs-upload.*")
    assert (storage / remote).read_bytes() == previous

    destination.write_bytes(b"Previous destination")
    for command in (GET_ACK, GET_DATA, GET_DONE):
        interrupt_transfer(client, get, upstream_port, "get", command,
                           signal.SIGTERM)
        await_cleanup(root, ".nasfs-download.*")
        assert destination.read_bytes() == b"Previous destination"

    for change in ("move", "retarget", "cancel-after-move"):
        original = root / f"{change}-original"
        original.mkdir()
        substitute = root / f"{change}-substitute"
        original_target = original / "local.bin"
        original_target.write_bytes(b"Previous destination")
        if change == "retarget":
            parent = root / "retarget-link"
            parent.symlink_to(original, target_is_directory=True)
            substitute.mkdir()
        else:
            parent = original

        def change_parent():
            assert list(original.glob(".nasfs-download.*")), change
            if change == "retarget":
                parent.unlink()
                parent.symlink_to(substitute, target_is_directory=True)
            else:
                original.rename(substitute)
                original.mkdir()

        args = ["get", remote, str(parent / "local.bin")]
        if change == "cancel-after-move":
            interrupt_transfer(client, args, upstream_port, "get", GET_DONE,
                               signal.SIGTERM, on_pause=change_parent)
        else:
            stderr = interrupt_transfer(client, args, upstream_port, "get", GET_DONE,
                                        None, before_forward=change_parent)
            assert b"Download destination directory changed" in stderr, stderr
        expected_parent = original if change == "retarget" else substitute
        assert (expected_parent / "local.bin").read_bytes() == b"Previous destination"
        unexpected_parent = substitute if change == "retarget" else original
        assert not (unexpected_parent / "local.bin").exists()
        await_cleanup(expected_parent, ".nasfs-download.*")
        await_cleanup(unexpected_parent, ".nasfs-download.*")

    for initially_present in (False, True):
        target = root / f"changed-during-download-{initially_present}.bin"
        other = root / "substitute.bin"
        other.write_bytes(b"Replacement from another writer")
        if initially_present:
            target.write_bytes(b"Previous destination")
        stderr = interrupt_transfer(client, ["get", remote, str(target)],
                                    upstream_port, "get", GET_DONE, None,
                                    before_forward=lambda: other.replace(target))
        assert b"Cannot publish download" in stderr, stderr
        assert target.read_bytes() == b"Replacement from another writer"
        await_cleanup(root, ".nasfs-download.*")

    interrupt_transfer(client, get, upstream_port, "get", GET_DONE, signal.SIGKILL)
    assert destination.read_bytes() == b"Previous destination"
    orphans = list(root.glob(".nasfs-download.*"))
    assert len(orphans) == 1, orphans
    subprocess.run([client, *get], check=True, stdout=subprocess.DEVNULL, timeout=10)
    assert destination.read_bytes() == source.read_bytes()
    assert orphans[0].is_file()
    orphans[0].unlink()

    stderr = interrupt_transfer(client, put, upstream_port, "get", PUT_RESULT, None)
    assert b"PUT outcome unknown" in stderr, stderr
    await_cleanup(staging, ".nasfs-upload.*")
    subprocess.run([client, *get], check=True, stdout=subprocess.DEVNULL)
    assert destination.read_bytes() == replacement.read_bytes()
    subprocess.run([client, "put", str(source), remote], check=True,
                   stdout=subprocess.DEVNULL)

    for cancelled in range(3):
        batch = [root / f"cancel-batch-{cancelled}-{index}.bin" for index in range(3)]
        for index, path in enumerate(batch):
            path.write_bytes(f"Batch member {index}".encode())
        interrupt_transfer(client, ["mput", *map(str, batch)], upstream_port,
                           "put", PUT_DONE, signal.SIGINT, occurrence=cancelled + 1)
        await_cleanup(staging, ".nasfs-upload.*")
        for path in batch[:cancelled]:
            subprocess.run([client, "get", path.name, str(destination)], check=True,
                           stdout=subprocess.DEVNULL)
            assert destination.read_bytes() == path.read_bytes()
        assert not any((storage / path.name).exists() for path in batch[cancelled:])

    batch = [root / f"download-batch-{index}.bin" for index in range(3)]
    for index, path in enumerate(batch):
        path.write_bytes(f"Download batch member {index}".encode())
    subprocess.run([client, "mput", *map(str, batch)], check=True,
                   stdout=subprocess.DEVNULL)
    for cancelled in range(3):
        output = root / f"cancel-mget-{cancelled}"
        output.mkdir()
        for path in batch:
            (output / path.name).write_bytes(b"Previous contents")
        interrupt_transfer(client, ["mget", *(path.name for path in batch)],
                           upstream_port, "get", GET_DONE, signal.SIGINT,
                           occurrence=cancelled + 1, cwd=output)
        await_cleanup(output, ".nasfs-download.*")
        for index, path in enumerate(batch):
            expected = path.read_bytes() if index < cancelled else b"Previous contents"
            assert (output / path.name).read_bytes() == expected

    previous = (storage / remote).read_bytes()
    stderr = interrupt_transfer(client, put, upstream_port, "put", PUT_DONE,
                                signal.SIGINT, int(server_pid))
    assert b"PUT outcome unknown" in stderr, stderr
    await_cleanup(staging, ".nasfs-upload.*")
    assert (storage / remote).read_bytes() == previous


if __name__ == "__main__":
    main()
