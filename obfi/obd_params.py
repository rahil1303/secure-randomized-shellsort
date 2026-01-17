# obd_params.py
# Fig. 5 (lines 1–10) + Lemma 1: parameter selection for OBD

import math
from dataclasses import dataclass
from typing import Iterable, List, Tuple, Optional

# ----- constants from the notes -----
C = 3 * math.sqrt(17) + 13         # ≈ 25.3693
K = C / 4.0                        # ≈ 6.3423


def get_lambda() -> int:
    return 128


@dataclass
class OBDParams:
    # False => guard not satisfied (run in fallback mode; skip OBD phase)
    valid: bool
    s: int
    n: int
    lam: int
    rho: int
    omega: int          # window size
    z: int              # number of buckets = ceil(n/omega)
    c_lb: float         # lower bound from ineq (3)
    c_ub: float         # upper bound from ineq (3)
    c_pick: float       # chosen c in [LB,UB]
    t: int              # capacity per bucket = ceil(c_pick)
    guard_val: float    # (2s/C - ln s), for visibility

    # Line 9 helper: subrange operations
    def get_subrange_index(self, value: int) -> int:
        """Return the subrange index Wi for a value."""
        if not self.valid:
            return 0
        return min(value // self.omega, self.z - 1)

    def get_subrange_bounds(self, i: int) -> Tuple[int, int]:
        """Return bounds for subrange Wi = [start, end]."""
        if not self.valid or i < 0 or i >= self.z:
            return (0, 0)
        start = i * self.omega
        end = min((i + 1) * self.omega - 1, self.n - 1)
        return start, end

    def value_in_subrange(self, value: int, subrange_index: int) -> bool:
        """Check if value is contained in Wi."""
        if not self.valid:
            return False
        start, end = self.get_subrange_bounds(subrange_index)
        return start <= value <= end


# ----- helpers implementing the exact math -----
def _triple_log_term(rho: float, s: int) -> float:
    # 3-nested log term used in the ω lower bound (Inequality 2)
    T0 = rho + math.log(s)
    T1 = T0 - math.log(K * T0)
    T2 = T0 - math.log(K * T1)
    T3 = T0 - math.log(K * T2)
    return T3


def _omega_min(n: int, s: int, rho: int) -> int:
    # Smallest integer ω satisfying Inequality (2); clamp to [1, n]
    factor = (C * n) / (2.0 * s)
    rhs = factor * _triple_log_term(rho, s)
    return max(1, min(n, math.ceil(rhs)))


def _c_interval(n: int, s: int, omega: int, rho: int) -> Tuple[float, float, float, float]:
    # Inequality (3) bounds for c
    sover = (s * omega) / float(n)              # s*ω/n
    X = rho - math.log(omega / (2.0 * n))       # ρ - ln(ω/(2n))
    lb = sover + 0.5 * X + 0.5 * math.sqrt(X * (8.0 * sover + X))
    ub = 2.0 * sover - 2.0 * math.sqrt(sover * X)
    return lb, ub, X, sover


# ====== 1) SINGLE VALUE API (for main) ======================================
def calculate_obd_parameters_single(
    s: int,
    n: int,
    lam: Optional[int] = None,
    c_choice: str = "mid",   # "mid" | "ub" | "lb"
) -> OBDParams:
    """
    Compute OBD parameters for a single (s, n) per Fig. 5 lines 1–10.

    Guard:
      If ((2s/C) - ln s) < λ, the theoretical guard is not satisfied.
      In that case we return valid=False and set fallback values (z=1, t=s).

    Otherwise:
      ρ = λ
      ω is the smallest integer satisfying inequality (2)
      c ∈ [LB,UB] from inequality (3), and t = ceil(c)
      z = ceil(n/ω)
    """
    lam = get_lambda() if lam is None else lam
    rho = lam

    guard_val = (2.0 * s) / C - math.log(s)
    if guard_val < lam:
        return OBDParams(
            valid=False,
            s=s,
            n=n,
            lam=lam,
            rho=rho,
            omega=n,
            z=1,
            c_lb=float("nan"),
            c_ub=float("nan"),
            c_pick=float("nan"),
            t=s,
            guard_val=guard_val,
        )

    omega = _omega_min(n, s, rho)
    c_lb, c_ub, _, _ = _c_interval(n, s, omega, rho)

    if c_choice == "ub":
        c_pick = math.nextafter(c_ub, -float("inf"))
    elif c_choice == "lb":
        c_pick = math.nextafter(c_lb, float("inf"))
    else:
        c_pick = 0.5 * (c_lb + c_ub)

    t = math.ceil(c_pick)
    z = math.ceil(n / float(omega))

    return OBDParams(True, s, n, lam, rho, omega, z, c_lb, c_ub, c_pick, t, guard_val)


# ====== 2) RANGE TESTER (table) =============================================
def _format_row(p: OBDParams) -> List[str]:
    if not p.valid:
        return [
            str(p.s), str(p.n), str(p.lam), f"{p.guard_val:.3f}",
            "FALLBACK", "-", "-", "-", "-", "-", "-"
        ]
    return [
        str(p.s),
        str(p.n),
        str(p.lam),
        f"{p.guard_val:.3f}",
        str(p.omega),
        str(p.z),
        f"{p.c_lb:.3f}",
        f"{p.c_ub:.3f}",
        f"{p.c_pick:.3f}",
        str(p.t),
        f"{(p.s * p.omega) / p.n:.3f}",  # sω/n
    ]


def _make_table(rows: List[List[str]], headers: List[str]) -> str:
    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]

    def fmt_line(cells):
        return " | ".join(c.ljust(w) for c, w in zip(cells, widths))

    sep = "-+-".join("-" * w for w in widths)
    lines = [fmt_line(headers), sep]
    lines += [fmt_line(r) for r in rows]
    return "\n".join(lines)


def test_obd_parameters_range(
    mode: str,
    n_list: Iterable[int],
    s_fixed: Optional[int] = None,
    lam: int = 128,
    c_choice: str = "mid",
) -> Tuple[List[OBDParams], str]:
    """
    Build a verification table over a range.

    mode:
      - "s_fixed": keep s = s_fixed, vary n over n_list
      - "s_eq_n":  set s = n for each n in n_list

    Returns: (records, pretty_table_string)
    """
    if mode not in {"s_fixed", "s_eq_n"}:
        raise ValueError("mode must be 's_fixed' or 's_eq_n'")

    params: List[OBDParams] = []
    if mode == "s_fixed":
        if s_fixed is None:
            raise ValueError("s_fixed is required for mode='s_fixed'")
        for n in n_list:
            params.append(calculate_obd_parameters_single(s_fixed, n, lam, c_choice))
    else:
        for n in n_list:
            params.append(calculate_obd_parameters_single(n, n, lam, c_choice))

    headers = ["s", "n", "λ", "guard", "ω", "z", "c_LB", "c_UB", "c_pick", "t", "sω/n"]
    table = _make_table([_format_row(p) for p in params], headers)
    return params, table


def test_obd_parameters_pairs(
    pairs, lam: int = 128, c_choice: str = "mid"
):
    """Test a list of arbitrary (s, n) pairs."""
    recs = [calculate_obd_parameters_single(s, n, lam, c_choice) for (s, n) in pairs]
    headers = ["s", "n", "λ", "guard", "ω", "z", "c_LB", "c_UB", "c_pick", "t", "sω/n"]
    table = _make_table([_format_row(p) for p in recs], headers)
    return recs, table


PROTOCOL_S = None      # number of elements
PROTOCOL_N = None      # range [0, n-1]
PROTOCOL_VALID = None  # whether guard is satisfied (True/False)
PROTOCOL_T = None      # bucket capacity / dummy count
PROTOCOL_OMEGA = None  # window size ω
PROTOCOL_Z = None      # number of buckets


def display_obd_parameter_summary(params: OBDParams) -> None:
    """Print a compact summary of the OBD parameter selection."""
    print("=" * 72)
    print("OBD parameter selection")
    print("=" * 72)
    print(f"s={params.s}, n={params.n}, λ={params.lam}")
    print(f"guard value: {params.guard_val:.3f}")

    if not params.valid:
        print("status: fallback (guard not satisfied for this setting)")
        print(f"fallback values: z=1, t={params.t}")
        print("=" * 72)
        return

    print("status: valid (guard satisfied)")
    print(f"ρ={params.rho}")
    print(f"ω={params.omega}, z={params.z}, t={params.t}")
    print(f"c in [{params.c_lb:.3f}, {params.c_ub:.3f}], chosen={params.c_pick:.3f}")
    print(f"sω/n={(params.s * params.omega) / params.n:.3f}")
    print("=" * 72)


def initialize_protocol_values(
    s: int,
    n: int,
    lam: int = 128,
    show_summary: bool = True,
):
    """Calculate and store protocol values globally for use across phases."""
    global PROTOCOL_S, PROTOCOL_N, PROTOCOL_VALID, PROTOCOL_T, PROTOCOL_OMEGA, PROTOCOL_Z

    params = calculate_obd_parameters_single(s, n, lam)

    PROTOCOL_S = params.s
    PROTOCOL_N = params.n
    PROTOCOL_VALID = params.valid
    PROTOCOL_T = params.t
    PROTOCOL_OMEGA = params.omega
    PROTOCOL_Z = params.z

    if show_summary:
        display_obd_parameter_summary(params)
    else:
        print(f"protocol params: s={PROTOCOL_S}, n={PROTOCOL_N}, valid={PROTOCOL_VALID}, "
              f"t={PROTOCOL_T}, ω={PROTOCOL_OMEGA}, z={PROTOCOL_Z}")

    return params


def get_protocol_values():
    """Return all stored protocol values as a tuple."""
    return PROTOCOL_S, PROTOCOL_N, PROTOCOL_VALID, PROTOCOL_T, PROTOCOL_OMEGA, PROTOCOL_Z


# ====== quick self-check =====================================================
if __name__ == "__main__":
    n_vals = [2500, 5000, 7500, 10000]

    recsA, tblA = test_obd_parameters_range(mode="s_fixed", s_fixed=2500, n_list=n_vals, lam=128)
    print("\nScenario A — s fixed (2500), n varies")
    print(tblA)

    recsB, tblB = test_obd_parameters_range(mode="s_eq_n", n_list=n_vals, lam=128)
    print("\nScenario B — s = n varies")
    print(tblB)

    custom_cases = [
        (1000, 100000),
        (5000, 50000),
        (10000, 1000000),
        (100000, 10000000000),
        (10**8, 10**14),
    ]
    recsC, tblC = test_obd_parameters_pairs(custom_cases, lam=128)
    print("\nScenario C — custom s/n combinations")
    print(tblC)

    # Line 9 helper checks (only runs for a valid parameter set)
    print("\n" + "=" * 60)
    print("Line 9 helper checks")
    print("=" * 60)

    test_params = next((p for p in recsC if p.valid), None)
    if test_params is None:
        print("no valid parameters found for Line 9 checks")
    else:
        print(f"s={test_params.s}, n={test_params.n}, ω={test_params.omega}, z={test_params.z}")
        for i in range(test_params.z):
            start, end = test_params.get_subrange_bounds(i)
            print(f"W{i} = [{start}, {end}]")

        test_values = [0, 1000, 50000, 100000, test_params.n - 1]
        for val in test_values:
            if val < test_params.n:
                wi = test_params.get_subrange_index(val)
                print(f"value {val} -> W{wi}")
