from obfi.crypto import SE_SDec, HGen, SE_SEnc
from obfi import obfi_params as params

import shellsort_pb2 as bos_pb2


def generate_hash_values_streaming(stub, Ke, Kb, total_elements):
    """
    Figure 7 (lines 4–17): Hash value generation (streaming).

    The client reads one encrypted element at a time from the server, decrypts it
    locally, computes k hash positions, encrypts each position, and streams the
    encrypted hash values back to the server. The server stores them in an EV
    array of length total_elements * k.
    """
    k = params.BLOOM_K
    m = params.BLOOM_M
    if k is None or m is None:
        raise RuntimeError("Bloom parameters not initialized (BLOOM_K / BLOOM_M).")

    expected = total_elements * k
    print("[phase1] hash generation (streaming)")
    print(f"[phase1] params: elements={total_elements}, k={k}, m={m}, expected_hashes={expected}")

    hash_functions = HGen(Kb, k)
    print(f"[phase1] generated {k} hash functions")

    init_request = bos_pb2.InitializeHashArrayRequest(expected_size=expected)
    init_response = stub.InitializeHashArray(init_request)
    if not init_response.success:
        print("[phase1] server initialization failed")
        return False

    print("[phase1] server ready for EV stream")

    hash_count = 0

    for i in range(total_elements):
        read_req = bos_pb2.ReadAbElementRequest(position=i)
        read_resp = stub.ReadAbElement(read_req)
        if not read_resp.success:
            print(f"[phase1] read failed: element_index={i}")
            continue

        try:
            element = SE_SDec(Ke, read_resp.element)
            if isinstance(element, str):
                element = int(element)

            for j in range(k):
                v = hash_functions[j](element) % m
                ev = SE_SEnc(Ke, v)

                send_req = bos_pb2.SendHashValueRequest(
                    encrypted_hash=ev,
                    index=hash_count,
                )
                send_resp = stub.SendHashValue(send_req)
                if not send_resp.success:
                    print(f"[phase1] send failed: ev_index={hash_count} (elem={i}, h={j})")
                    continue

                hash_count += 1

            if (i + 1) % 100 == 0:
                print(f"[phase1] progress: {i + 1}/{total_elements} elements, {hash_count} hashes")

        except Exception as e:
            print(f"[phase1] error processing element_index={i}: {e}")

    print(f"[phase1] stream complete: sent={hash_count}, expected={expected}, match={hash_count == expected}")

    finalize_req = bos_pb2.FinalizeHashArrayRequest()
    finalize_resp = stub.FinalizeHashArray(finalize_req)
    if not finalize_resp.success:
        print("[phase1] server finalization failed")
        return False

    print(f"[phase1] server finalized EV: size={hash_count}")
    return True
