"""
Full pipeline orchestrator.

Runs the end-to-end workflow by invoking the existing OBFI modules:
  Phase 0: obfi.data_creation_0.run_phase0_upload
  Phase 1: obfi.obfi_gen_hash_2.generate_hash_values_streaming
  Phase 2: Randomized Shell Sort client (client.py)

This file is intended as a runnable driver for local experiments and integration
testing. It does not change protocol logic; it only wires the phases together.
"""

import os
import sys
import random
import grpc

import shellsort_pb2
import shellsort_pb2_grpc

# Ensure local imports take precedence (for local `obfi/` and generated stubs).
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if _CURRENT_DIR not in sys.path:
    sys.path.insert(0, _CURRENT_DIR)

from obfi.data_creation_0 import run_phase0_upload
from obfi.obfi_gen_hash_2 import generate_hash_values_streaming

from obfi.crypto import SE_SGen, SE_SEnc, SE_SDec
import obfi.obfi_params as obfi_params

from client import ShellSortClient, randomized_shellsort


class KeyWrapper:
    """
    Adapter used by the sorting client.

    The sorting client expects an object exposing:
      - encrypt(int) -> bytes
      - decrypt(bytes) -> int

    This wrapper bridges those calls to the existing OBFI symmetric encryption
    helpers used in Phase 0/1.
    """

    def __init__(self, se_key):
        self.se_key = se_key

    def encrypt(self, value: int) -> bytes:
        return SE_SEnc(self.se_key, value)

    def decrypt(self, encrypted_value: bytes) -> int:
        result = SE_SDec(self.se_key, encrypted_value)
        if isinstance(result, str):
            return int(result)
        return result


def run_full_pipeline(s: int = 100, n: int = 10_000, k: int = 4, m=None, p: float = 1e-3) -> bool:
    """
    Run the complete pipeline.

    Args:
        s: number of elements
        n: element range [0, n-1]
        k: number of hash functions
        m: Bloom filter size (computed if None)
        p: false positive rate (used to compute m when m is None)

    Returns:
        True if the final decrypted output is sorted, otherwise False.
    """
    # Calculate Bloom filter size if not provided.
    if m is None:
        import math
        m = math.ceil(-s * math.log(p) / (math.log(2) ** 2))

    # Configure Bloom filter parameters used by the OBFI modules.
    obfi_params.BLOOM_K = k
    obfi_params.BLOOM_M = m
    obfi_params.BLOOM_ENHANCED_M = 2 * m

    # Client-side keys used by the OBFI modules.
    Ke = SE_SGen()  # element encryption key
    Kb = SE_SGen()  # hashing key / auxiliary key

    channel = grpc.insecure_channel("localhost:50051")
    stub = shellsort_pb2_grpc.ShellSortServiceStub(channel)

    try:
        # Phase 0: upload encrypted elements
        ok = run_phase0_upload(Ke, stub, s=s, n=n)
        if not ok:
            raise RuntimeError("Phase 0 failed")

        # Phase 1: generate and stream encrypted hash positions (EV)
        ok = generate_hash_values_streaming(stub, Ke, Kb, s)
        if not ok:
            raise RuntimeError("Phase 1 failed")

        # Switch server input to the streamed hash array.
        use_resp = stub.UseHashArrayForSorting(shellsort_pb2.UseHashArrayForSortingRequest())
        if not use_resp.success:
            raise RuntimeError("Failed to switch server to sorting mode")

        array_size = use_resp.array_size

        # Phase 2: run Randomized Shell Sort using an encryption adapter.
        encryption_wrapper = KeyWrapper(Ke)
        client = ShellSortClient(channel, encryption_wrapper)
        randomized_shellsort(client, array_size)

        final_encrypted, total_comparisons, total_writes = client.get_final_array()
        final_decrypted = [encryption_wrapper.decrypt(enc) for enc in final_encrypted]
        is_sorted = final_decrypted == sorted(final_decrypted)

        print("pipeline_result:")
        print("  sorted:", is_sorted)
        print("  array_size:", array_size)
        print("  comparisons:", total_comparisons)
        print("  writes:", total_writes)
        print("  head:", final_decrypted[:32])

        return is_sorted

    except Exception as e:
        print("pipeline_error:", e)
        import traceback
        traceback.print_exc()
        return False

    finally:
        channel.close()


if __name__ == "__main__":
    random.seed(42)
    ok = run_full_pipeline(
        s=100,
        n=10_000,
        k=7,
        # m is computed from (s, p)
    )
    print("success:", ok)
