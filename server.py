"""
Randomized Shell Sort - gRPC Server

This server supports a three-phase pipeline:
- Phase 0: Encrypted element storage
- Phase 1: Encrypted hash (EV) array construction
- Phase 2: Oblivious sorting using Randomized Shell Sort

The server never performs decryption and operates only on ciphertexts.
"""

import grpc
from concurrent import futures
import random
from typing import Dict, List, Tuple

import shellsort_pb2
import shellsort_pb2_grpc


class ShellSortServer(shellsort_pb2_grpc.ShellSortServiceServicer):
    def __init__(self):
        # Phase 0: encrypted element storage
        self.element_array: List[bytes] = []
        self.element_expected: int = 0
        self.element_received: int = 0
        self.element_finalized: bool = False

        # Phase 1: encrypted hash array (EV)
        self.hash_array: List[bytes] = []
        self.hash_expected: int = 0
        self.hash_received: int = 0
        self.hash_finalized: bool = False

        # Phase 2: encrypted array used for sorting
        self.encrypted_array: List[bytes] = []
        self.n: int = 0

        # Metrics
        self.comparison_count: int = 0
        self.write_count: int = 0

        # Permutation cache: (size, seed) -> permutation
        self.perm_cache: Dict[Tuple[int, int], List[int]] = {}

        print("[SERVER] Initialized")

    # ======================================================================
    # Phase 0: Encrypted element storage
    # ======================================================================

    def InitializeInitialData(self, request, context):
        """Prepare server to receive encrypted elements."""
        total = request.total_elements
        if total <= 0:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "total_elements must be > 0")

        self.element_array = [b""] * total
        self.element_expected = total
        self.element_received = 0
        self.element_finalized = False

        return shellsort_pb2.InitialDataResponse(success=True)

    def UploadInitialDataBatch(self, request, context):
        """Store a batch of encrypted elements."""
        batch = request.batch_elements
        start_idx = request.batch_start_index
        batch_size = request.batch_size

        if batch_size != len(batch):
            return shellsort_pb2.InitialDataBatchResponse(
                success=False,
                error_message="Batch size mismatch"
            )

        for i, elem in enumerate(batch):
            idx = start_idx + i
            if 0 <= idx < self.element_expected:
                self.element_array[idx] = elem
                self.element_received += 1
            else:
                return shellsort_pb2.InitialDataBatchResponse(
                    success=False,
                    error_message=f"Index {idx} out of range"
                )

        return shellsort_pb2.InitialDataBatchResponse(success=True)

    def FinalizeInitialData(self, request, context):
        """Finalize element upload phase."""
        self.element_finalized = True
        success = self.element_received == self.element_expected

        return shellsort_pb2.FinalizeInitialDataResponse(
            success=success,
            total_stored=self.element_received
        )

    def ReadAbElement(self, request, context):
        """Return encrypted element at a given position."""
        if not self.element_finalized:
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, "Element data not finalized")

        pos = request.position
        if not (0 <= pos < len(self.element_array)):
            context.abort(grpc.StatusCode.OUT_OF_RANGE, "Position out of range")

        return shellsort_pb2.ReadAbElementResponse(
            success=True,
            element=self.element_array[pos]
        )

    # ======================================================================
    # Phase 1: Hash array (EV) construction
    # ======================================================================

    def InitializeHashArray(self, request, context):
        """Prepare server to receive encrypted hash values."""
        expected = int(request.expected_size)
        if expected <= 0:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "expected_size must be > 0")

        self.hash_array = [b""] * expected
        self.hash_expected = expected
        self.hash_received = 0
        self.hash_finalized = False

        return shellsort_pb2.InitializeHashArrayResponse(
            success=True,
            expected_size=expected
        )

    def SendHashValue(self, request, context):
        """Store a single encrypted hash value."""
        if not self.hash_array:
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, "Hash array not initialized")

        idx = int(request.index)
        if not (0 <= idx < self.hash_expected):
            context.abort(grpc.StatusCode.OUT_OF_RANGE, "Hash index out of range")

        self.hash_array[idx] = request.encrypted_hash
        self.hash_received += 1

        return shellsort_pb2.SendHashValueResponse(success=True)

    def FinalizeHashArray(self, request, context):
        """Finalize hash array construction."""
        self.hash_finalized = True
        success = self.hash_received == self.hash_expected

        return shellsort_pb2.FinalizeHashArrayResponse(
            success=success,
            received=self.hash_received,
            expected=self.hash_expected
        )

    def UseHashArrayForSorting(self, request, context):
        """Use the hash array as input for the sorting phase."""
        if not self.hash_finalized:
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, "Hash array not finalized")

        self.encrypted_array = list(self.hash_array)
        self.n = len(self.encrypted_array)

        self.comparison_count = 0
        self.write_count = 0
        self.perm_cache.clear()

        return shellsort_pb2.UseHashArrayForSortingResponse(
            success=True,
            array_size=self.n
        )

    # ======================================================================
    # Phase 2: Randomized Shell Sort (oblivious operations)
    # ======================================================================

    def Initialize(self, request, context):
        """Directly initialize sorting array."""
        self.encrypted_array = list(request.encrypted_array)
        self.n = len(self.encrypted_array)

        self.comparison_count = 0
        self.write_count = 0
        self.perm_cache.clear()

        return shellsort_pb2.InitResponse(
            success=True,
            array_size=self.n
        )

    def GetPair(self, request, context):
        """Return two encrypted values at fixed indices."""
        self.comparison_count += 1

        idx_a = request.index_a
        idx_b = request.index_b
        if not (0 <= idx_a < self.n and 0 <= idx_b < self.n):
            context.abort(grpc.StatusCode.OUT_OF_RANGE, "Index out of range")

        return shellsort_pb2.GetPairResponse(
            encrypted_a=self.encrypted_array[idx_a],
            encrypted_b=self.encrypted_array[idx_b],
        )

    def WritePair(self, request, context):
        """Blindly overwrite two encrypted values."""
        idx_a = request.index_a
        idx_b = request.index_b
        if not (0 <= idx_a < self.n and 0 <= idx_b < self.n):
            context.abort(grpc.StatusCode.OUT_OF_RANGE, "Index out of range")

        self.encrypted_array[idx_a] = request.new_encrypted_a
        self.encrypted_array[idx_b] = request.new_encrypted_b
        self.write_count += 1

        return shellsort_pb2.WritePairResponse(success=True)

    def GetMate(self, request, context):
        """Return mate[i] from a pseudorandom permutation."""
        size = request.size
        seed = request.seed
        i = request.index

        if not (0 <= i < size):
            context.abort(grpc.StatusCode.OUT_OF_RANGE, "Mate index out of range")

        key = (size, seed)
        if key not in self.perm_cache:
            rng = random.Random(seed)
            perm = list(range(size))
            rng.shuffle(perm)
            self.perm_cache[key] = perm

        return shellsort_pb2.MateResponse(mate=self.perm_cache[key][i])

    def GetFinalArray(self, request, context):
        """Return final encrypted array and operation counts."""
        return shellsort_pb2.FinalArrayResponse(
            encrypted_array=self.encrypted_array,
            total_comparisons=self.comparison_count,
            total_writes=self.write_count,
        )


def serve():
    """Start the gRPC server."""
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    shellsort_pb2_grpc.add_ShellSortServiceServicer_to_server(
        ShellSortServer(), server
    )

    server.add_insecure_port("[::]:50051")
    server.start()
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
