import json
import secrets
import grpc

import shellsort_pb2 as bloom_filter_pb2
import shellsort_pb2_grpc as bloom_filter_pb2_grpc

from obfi.crypto import SE_SEnc, SE_SDec
import obfi.obd_params as obd_params


def run_phase0_upload(Ke, grpc_stub, s=None, n=None):
    """
    Phase 0: create and upload encrypted elements to the server.

    Parameter precedence:
      1) use passed (s, n) if both are provided (and initialize OBD globals)
      2) otherwise use existing OBD globals if available
      3) otherwise fall back to defaults and initialize OBD globals
    """
    if s is not None and n is not None:
        print(f"[phase0] using passed parameters: s={s}, n={n}")
        obd_params.initialize_protocol_values(s, n)
        actual_s, actual_n = s, n
    elif obd_params.PROTOCOL_S is not None and obd_params.PROTOCOL_N is not None:
        print("[phase0] using existing obd_params globals")
        actual_s, actual_n = obd_params.PROTOCOL_S, obd_params.PROTOCOL_N
    else:
        actual_s, actual_n = 5000, 50000
        print(f"[phase0] no parameters provided; using defaults: s={actual_s}, n={actual_n}")
        obd_params.initialize_protocol_values(actual_s, actual_n)

    print(f"[phase0] parameters: s={actual_s}, n={actual_n}, valid={obd_params.PROTOCOL_VALID}")

    # Initialize server to receive elements.
    try:
        init_req = bloom_filter_pb2.InitialDataRequest(total_elements=actual_s)
        resp = grpc_stub.InitializeInitialData(init_req)
        if not resp.success:
            print("[phase0] server initialization failed")
            return False
        print(f"[phase0] server initialized: total_elements={actual_s}")
    except Exception as e:
        # Some server variants might not require an explicit initialize call.
        print(f"[phase0] server initialization error: {e}")

    generated_values = []
    successful_uploads = 0

    # Stream elements via single-element batch uploads.
    for i in range(actual_s):
        try:
            v = secrets.randbelow(actual_n)
            generated_values.append(v)

            ev = SE_SEnc(Ke, str(v))
            batch_req = bloom_filter_pb2.InitialDataBatchRequest(
                batch_elements=[ev],
                batch_start_index=i,
                batch_size=1,
            )
            resp = grpc_stub.UploadInitialDataBatch(batch_req)

            if resp.success:
                successful_uploads += 1
            else:
                print(f"[phase0] upload failed at index={i}: {resp.error_message}")

        except Exception as e:
            print(f"[phase0] error uploading index={i}: {e}")

        if i % 1000 == 0 or i == actual_s - 1:
            print(f"[phase0] progress: {i + 1}/{actual_s} uploaded (ok={successful_uploads})")

    # Finalize element upload if supported.
    try:
        finalize_req = bloom_filter_pb2.FinalizeInitialDataRequest()
        resp = grpc_stub.FinalizeInitialData(finalize_req)
        if resp.success:
            print(f"[phase0] finalized: {successful_uploads}/{actual_s} elements uploaded")
        else:
            print(f"[phase0] finalization warning: {resp.error_message}")
    except Exception as e:
        print(f"[phase0] finalization error: {e}")

    success_rate = successful_uploads / actual_s if actual_s > 0 else 0.0
    success = success_rate >= 0.95

    if not success:
        print(f"[phase0] failed: success_rate={success_rate:.3f}")
        return False

    print(f"[phase0] success: success_rate={success_rate:.3f}")

    # Verification: read back and compare against generated_values.
    verify_phase0_server_storage(Ke, grpc_stub, generated_values, actual_s)

    try:
        with open("original_elements.json", "w") as f:
            json.dump(generated_values, f)
        print(f"[phase0] wrote original_elements.json ({len(generated_values)} values)")
    except Exception as e:
        print(f"[phase0] could not write original_elements.json: {e}")

    return True


def verify_phase0_server_storage(Ke, grpc_stub, expected_values, total_elements, sample_size=2500):
    """Verify server storage by reading back a sample of positions and decrypting them."""
    limit = min(sample_size, total_elements)
    print("=" * 60)
    print(f"[phase0] server storage verification (sample={limit})")
    print("=" * 60)

    if expected_values:
        print(f"[phase0] expected range: [0, {max(expected_values)}]")
    else:
        print("[phase0] expected range: N/A")

    stored_values = []
    read_errors = 0

    for i in range(limit):
        try:
            req = bloom_filter_pb2.ReadAbElementRequest(position=i)
            resp = grpc_stub.ReadAbElement(req)

            if resp.success and resp.element:
                decrypted_value = SE_SDec(Ke, resp.element)
                stored_values.append((i, decrypted_value, expected_values[i]))
            else:
                read_errors += 1
        except Exception:
            read_errors += 1

    matches = 0
    mismatches = 0

    preview = stored_values[:25]
    print(f"[phase0] preview (first {len(preview)}):")
    for pos, stored_val, expected_val in preview:
        stored_int = int(stored_val) if stored_val.isdigit() else stored_val
        ok = stored_int == expected_val
        matches += 1 if ok else 0
        mismatches += 0 if ok else 1
        status = "OK" if ok else "MISMATCH"
        print(f"  [{pos:4d}] expected={expected_val:5d} stored={stored_val:>5} {status}")

    for pos, stored_val, expected_val in stored_values[25:]:
        stored_int = int(stored_val) if stored_val.isdigit() else stored_val
        if stored_int == expected_val:
            matches += 1
        else:
            mismatches += 1

    checked = matches + mismatches
    if checked > 0:
        rate = (matches / checked) * 100.0
        print(f"[phase0] verification: matches={matches}, mismatches={mismatches}, "
              f"read_errors={read_errors}, success_rate={rate:.1f}%")
    else:
        print(f"[phase0] verification: no values checked (read_errors={read_errors})")

    if expected_values:
        avg = sum(expected_values) / len(expected_values)
        print(f"[phase0] generated stats: min={min(expected_values)} max={max(expected_values)} "
              f"avg={avg:.1f} unique={len(set(expected_values))}/{len(expected_values)}")


def run_phase0_upload_simple(Ke, grpc_stub, s=5000, n=50000):
    """Backward-compatible wrapper."""
    return run_phase0_upload(Ke, grpc_stub, s, n)


def run_phase0_upload_original(Ke, grpc_stub, s=5000, n=50000):
    """Backward-compatible wrapper."""
    return run_phase0_upload(Ke, grpc_stub, s, n)


if __name__ == "__main__":
    from obfi.crypto import SE_SGen

    print("[phase0] manual test driver")
    Ke = SE_SGen()

    s = 2500
    n = 50000

    channel = grpc.insecure_channel("localhost:50051")
    stub = bloom_filter_pb2_grpc.ShellSortServiceStub(channel)

    ok = run_phase0_upload(Ke, stub, s, n)
    print(f"[phase0] result: {ok}")

    s_val, n_val, valid, t_val, omega_val, z_val = obd_params.get_protocol_values()
    print("[phase0] protocol globals:")
    print(f"  PROTOCOL_S={s_val}")
    print(f"  PROTOCOL_N={n_val}")
    print(f"  PROTOCOL_VALID={valid}")
    print(f"  PROTOCOL_T={t_val}")
    print(f"  PROTOCOL_OMEGA={omega_val}")
    print(f"  PROTOCOL_Z={z_val}")
