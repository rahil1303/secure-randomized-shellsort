# obfi_params.py
# Bloom filter parameter utilities (shellsort-compatible; server init deferred)

import math
import obfi.obd_params as obd_params
from obfi.crypto import SE_SGen, HGen

BLOOM_M = None
BLOOM_K = None
BLOOM_ENHANCED_M = None


class BloomFilterParameters:
    """
    Compute Bloom filter parameters using standard formulas.

    Includes the OBFI-style "2m" layout (enhanced_m) used for obfuscation on the
    server side, even if allocation is not performed in this module.
    """

    def __init__(self, n: int, p: float):
        self.n = n
        self.p = p

        self.m = self._calculate_m()
        self.k = self._calculate_k()

        self.enhanced_m = 2 * self.m
        self.usable_range = (0, self.m - 1)
        self.padding_range = (self.m, self.enhanced_m - 1)

        self.memory_standard = self.m / 8
        self.memory_enhanced = self.enhanced_m / 8
        self.memory_overhead = self.memory_enhanced - self.memory_standard

    def _calculate_m(self) -> int:
        numerator = -self.n * math.log(self.p)
        denominator = (math.log(2)) ** 2
        return math.ceil(numerator / denominator)

    def _calculate_k(self) -> int:
        ratio = self.m / self.n
        return math.ceil(ratio * math.log(2))

    def verify_false_positive_rate(self) -> float:
        exponent = -self.k * self.n / self.m
        return (1 - math.exp(exponent)) ** self.k

    def get_obfi_properties(self):
        return {
            "standard_array_size": self.m,
            "enhanced_array_size": self.enhanced_m,
            "usable_positions": f"[0, {self.m - 1}]",
            "padding_positions": f"[{self.m}, {self.enhanced_m - 1}]",
            "obfuscation_factor": 2.0,
            "apparent_density": 0.25,
            "memory_overhead_kb": self.memory_overhead / 1024,
        }

    def display_parameters(self) -> None:
        print("=" * 72)
        print("Bloom filter parameter calculation")
        print("=" * 72)
        print(f"input: n={self.n}, p={self.p}")
        print(f"standard: m={self.m} bits, k={self.k}, mem={(self.memory_standard / 1024):.2f} KB")
        print(f"enhanced: 2m={self.enhanced_m} bits, mem={(self.memory_enhanced / 1024):.2f} KB")
        print(f"ranges: usable=[0, {self.m - 1}], padding=[{self.m}, {self.enhanced_m - 1}]")
        print(f"p_check: target={self.p}, actual={self.verify_false_positive_rate():.6f}")
        print("note: server allocation is deferred (shellsort server does not expose BF APIs)")
        print("=" * 72)


def setup_bloom_filter_phase3(n: int | None = None, p: float = 1e-3) -> BloomFilterParameters:
    """
    Compute and publish Bloom parameters via module globals:
      - BLOOM_M, BLOOM_K, BLOOM_ENHANCED_M

    If n is not provided, use obd_params.PROTOCOL_S if available.
    """
    if n is None:
        if obd_params.PROTOCOL_S is None:
            raise ValueError("n not provided and obd_params.PROTOCOL_S is not set")
        n = obd_params.PROTOCOL_S

    print("[phase3] bloom parameter setup")
    print(f"[phase3] n={n}, p={p}")

    bloom_params = BloomFilterParameters(n, p)
    bloom_params.display_parameters()

    global BLOOM_M, BLOOM_K, BLOOM_ENHANCED_M
    BLOOM_M = bloom_params.m
    BLOOM_K = bloom_params.k
    BLOOM_ENHANCED_M = bloom_params.enhanced_m

    return bloom_params


def generate_hash_functions(bloom_params: BloomFilterParameters, hash_key=None):
    """
    Generate k hash functions (client-side only).

    Returns:
      (hash_key, hash_functions)
    """
    if hash_key is None:
        hash_key = SE_SGen()

    print(f"[phase3] generating hash functions: k={bloom_params.k}")
    hash_functions = HGen(hash_key, bloom_params.k)

    test_element = 42865
    positions = [h(test_element) % bloom_params.m for h in hash_functions]
    in_range = all(0 <= p < bloom_params.m for p in positions)

    print(f"[phase3] sanity: element={test_element} -> positions={positions}, in_range={in_range}")

    return hash_key, hash_functions
