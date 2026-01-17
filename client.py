"""
Randomized Shell Sort - gRPC Client

The client holds the encryption key and performs all plaintext comparisons.
The server stores ciphertexts and executes fixed-pattern reads/writes.

This client implementation is streaming: it only decrypts and processes two
values at a time during compare-exchange operations.
"""

import grpc
import random
import secrets
from typing import List, Tuple

import shellsort_pb2
import shellsort_pb2_grpc
from encryption import SecureEncryption


class ShellSortClient:
    """Client that orchestrates sorting and performs compare-exchange locally."""

    def __init__(self, channel, encryption: SecureEncryption):
        self.stub = shellsort_pb2_grpc.ShellSortServiceStub(channel)
        self.encryption = encryption

        # Small client-side state (excluding gRPC request/response objects)
        self.current_seed = 0

    def initialize_server(self, encrypted_data: List[bytes]) -> int:
        """Upload an encrypted array to the server and return its size."""
        response = self.stub.Initialize(
            shellsort_pb2.InitRequest(encrypted_array=encrypted_data)
        )
        if not response.success:
            raise RuntimeError("Server initialization failed")
        return response.array_size

    def generate_seed(self) -> int:
        """Generate a seed for the permutation used in a region compare-exchange."""
        self.current_seed = secrets.randbelow(1_000_000) + 1
        return self.current_seed

    def get_mate_from_server(self, size: int, seed: int, i: int) -> int:
        """Fetch mate[i] from the server (streamed; client does not store the permutation)."""
        resp = self.stub.GetMate(shellsort_pb2.MateRequest(size=size, seed=seed, index=i))
        return resp.mate

    def compare_and_prepare_writes(self, idx_a: int, idx_b: int) -> Tuple[bytes, bytes]:
        """
        Read two ciphertexts, decrypt, compare, and return two fresh ciphertexts.

        Direction:
          - idx_a < idx_b: enforce ascending order
          - idx_a > idx_b: enforce descending order
        """
        resp = self.stub.GetPair(
            shellsort_pb2.GetPairRequest(index_a=idx_a, index_b=idx_b)
        )

        a = self.encryption.decrypt(resp.encrypted_a)
        b = self.encryption.decrypt(resp.encrypted_b)

        if idx_a < idx_b:
            x, y = (a, b) if a <= b else (b, a)
        else:
            x, y = (a, b) if a >= b else (b, a)

        # Re-encrypt outputs to avoid reusing ciphertext tokens across writes.
        return self.encryption.encrypt(x), self.encryption.encrypt(y)

    def write_pair(self, idx_a: int, idx_b: int, new_enc_a: bytes, new_enc_b: bytes) -> None:
        """Blind overwrite of two ciphertexts."""
        self.stub.WritePair(
            shellsort_pb2.WritePairRequest(
                index_a=idx_a,
                index_b=idx_b,
                new_encrypted_a=new_enc_a,
                new_encrypted_b=new_enc_b,
            )
        )

    def get_final_array(self):
        """Fetch the final encrypted array and server-side operation counts."""
        response = self.stub.GetFinalArray(shellsort_pb2.FinalArrayRequest())
        return (
            list(response.encrypted_array),
            response.total_comparisons,
            response.total_writes,
        )


def region_compare_exchange(
    client: ShellSortClient,
    region_a_start: int,
    region_b_start: int,
    region_size: int,
    c: int = 4,
) -> None:
    """
    Perform c random matchings between two regions.

    For each matching:
      - server provides a permutation mate[i]
      - client performs compare-exchange on (region_a_start + i, region_b_start + mate[i])
      - server overwrites both ciphertext positions
    """
    for _ in range(c):
        seed = client.generate_seed()

        for i in range(region_size):
            mate_i = client.get_mate_from_server(region_size, seed, i)
            idx_a = region_a_start + i
            idx_b = region_b_start + mate_i

            new_enc_a, new_enc_b = client.compare_and_prepare_writes(idx_a, idx_b)
            client.write_pair(idx_a, idx_b, new_enc_a, new_enc_b)


def randomized_shellsort(client: ShellSortClient, n: int) -> None:
    """
    Randomized Shell Sort using shaker + brick passes over region partitions.

    Assumes n is a power of two (caller can pad with a sentinel value if needed).
    """
    print("\n" + "=" * 70)
    print("RANDOMIZED SHELL SORT - CLIENT ORCHESTRATING")
    print(f"Array size: {n}")
    print("=" * 70)

    offset = n // 2
    iteration = 1

    while offset >= 1:
        num_regions = n // offset
        print(f"\n[client] iteration {iteration}: offset={offset} ({num_regions} regions)")

        # Shaker pass: forward adjacent, then backward adjacent.
        for i in range(num_regions - 1):
            region_compare_exchange(client, i * offset, (i + 1) * offset, offset)

        for i in range(num_regions - 2, -1, -1):
            region_compare_exchange(client, (i + 1) * offset, i * offset, offset)

        # Brick pass: 3-hop, 2-hop, even-adjacent, odd-adjacent.
        if num_regions >= 4:
            for i in range(num_regions - 3):
                region_compare_exchange(client, i * offset, (i + 3) * offset, offset)

        if num_regions >= 3:
            for i in range(num_regions - 2):
                region_compare_exchange(client, i * offset, (i + 2) * offset, offset)

        for i in range(0, num_regions - 1, 2):
            region_compare_exchange(client, i * offset, (i + 1) * offset, offset)

        for i in range(1, num_regions - 1, 2):
            region_compare_exchange(client, i * offset, (i + 1) * offset, offset)

        offset //= 2
        iteration += 1

    print("\n" + "=" * 70)
    print("[client] sorting complete")
    print("=" * 70)


def run_client() -> None:
    """Example driver for running the client against a local server."""
    random.seed(42)

    # Example input (hash positions). In the full pipeline, these are derived from hashing.
    hash_positions = [742, 123, 891, 45, 567, 823, 234, 678, 456, 12]

    # Pad to a power of two if needed.
    n = len(hash_positions)
    if n & (n - 1) != 0:
        next_power = 1
        while next_power < n:
            next_power *= 2
        while len(hash_positions) < next_power:
            hash_positions.append(999999)
        n = next_power

    encryption = SecureEncryption()
    encrypted_positions: List[bytes] = [encryption.encrypt(pos) for pos in hash_positions]

    channel = grpc.insecure_channel("localhost:50051")
    client = ShellSortClient(channel, encryption)

    array_size = client.initialize_server(encrypted_positions)

    print("\n[client] starting randomized shell sort...")
    randomized_shellsort(client, array_size)

    final_encrypted, total_comparisons, total_writes = client.get_final_array()
    final_decrypted = [encryption.decrypt(enc) for enc in final_encrypted]

    print("\n[client] verification")
    print("sorted:", final_decrypted == sorted(final_decrypted))
    print("comparisons:", total_comparisons)
    print("writes:", total_writes)


if __name__ == "__main__":
    run_client()
