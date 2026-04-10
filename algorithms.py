"""
algorithms.py — Mathematical primitives for the semantic firewall.

AhoCorasick   — multi-pattern string matching in O(n + m) time.
BloomFilter   — probabilistic set membership in O(k) time and O(m) bits space.
levenshtein   — edit distance between two strings in O(|a|*|b|) time, O(min) space.
"""

import hashlib
import math
from collections import deque


# ── Aho-Corasick ──────────────────────────────────────────────────────────────

class AhoCorasick:
    """
    Finite automaton for simultaneous multi-pattern matching.

    Construction: O(sum of pattern lengths)
    Search:       O(text length + number of matches)

    vs naive approach — checking each of P forbidden words independently
    against a fact of length L costs O(P * L) per fact. Aho-Corasick reduces
    this to O(L) regardless of how many patterns exist, by encoding all patterns
    into a single trie with failure links so the scan never backtracks.

    How the automaton works:
      - goto[state][char]  → next state (trie transitions)
      - fail[state]        → fallback state when no goto exists (failure links)
      - output[state]      → patterns that end at this state

    Failure links are built via BFS so that when a partial match fails, the
    automaton jumps to the longest proper suffix that is also a prefix of some
    pattern — instead of restarting from scratch.
    """

    def __init__(self, patterns: list[str]):
        self.goto: list[dict[str, int]] = [{}]
        self.fail: list[int] = [0]
        self.output: list[list[str]] = [[]]
        self._build(patterns)

    def _build(self, patterns: list[str]) -> None:
        # Phase 1 — build trie (goto function)
        for pattern in patterns:
            state = 0
            for ch in pattern:
                if ch not in self.goto[state]:
                    self.goto[state][ch] = len(self.goto)
                    self.goto.append({})
                    self.fail.append(0)
                    self.output.append([])
                state = self.goto[state][ch]
            self.output[state].append(pattern)

        # Phase 2 — build failure links via BFS
        q: deque[int] = deque()
        for ch, s in self.goto[0].items():
            self.fail[s] = 0
            q.append(s)

        while q:
            r = q.popleft()
            for ch, s in self.goto[r].items():
                q.append(s)
                state = self.fail[r]
                while state != 0 and ch not in self.goto[state]:
                    state = self.fail[state]
                self.fail[s] = self.goto[state].get(ch, 0)
                if self.fail[s] == s:
                    self.fail[s] = 0
                # merge outputs: patterns reachable via failure chain
                self.output[s] = self.output[s] + self.output[self.fail[s]]

    def search(self, text: str) -> list[tuple[int, str]]:
        """
        Scan text once, returning (start_pos, matched_pattern) for every hit.
        """
        state = 0
        results = []
        for i, ch in enumerate(text):
            while state != 0 and ch not in self.goto[state]:
                state = self.fail[state]
            state = self.goto[state].get(ch, 0)
            for pattern in self.output[state]:
                results.append((i - len(pattern) + 1, pattern))
        return results


# ── Bloom Filter ──────────────────────────────────────────────────────────────

class BloomFilter:
    """
    Probabilistic set membership using a compact bit array.

    Guarantees: no false negatives — if an item was add()ed, __contains__
                always returns True.
    Trade-off:  small false positive rate p — a non-member may appear present.

    Optimal parameters (derived from desired capacity n and error rate p):
        m = ceil(-n * ln(p) / ln(2)^2)   bits
        k = round((m / n) * ln(2))       hash functions

    At high emit() throughput this is faster than a dict/set lookup because:
      - k independent bit checks vs one full hash + bucket dereference
      - the bit array fits in CPU cache; large sets may not
      - false positives fall through to the exact set check below

    Double-hashing: we generate k positions from two base hashes (MD5, SHA-1)
    using  h(i) = (h1 + i*h2) mod m  rather than k independent hash calls.
    """

    def __init__(self, capacity: int, error_rate: float = 0.01):
        self.capacity = capacity
        self.m = math.ceil(-capacity * math.log(error_rate) / (math.log(2) ** 2))
        self.k = max(1, round((self.m / capacity) * math.log(2)))
        self._bits = bytearray(math.ceil(self.m / 8))

    # -- properties -----------------------------------------------------------

    @property
    def bit_count(self) -> int:
        return self.m

    @property
    def hash_count(self) -> int:
        return self.k

    # -- internal -------------------------------------------------------------

    def _positions(self, item: str) -> list[int]:
        h1 = int(hashlib.md5(item.encode()).hexdigest(), 16)
        h2 = int(hashlib.sha256(item.encode()).hexdigest(), 16)
        return [(h1 + i * h2) % self.m for i in range(self.k)]

    # -- public ---------------------------------------------------------------

    def add(self, item: str) -> None:
        for pos in self._positions(item):
            self._bits[pos // 8] |= 1 << (pos % 8)

    def __contains__(self, item: str) -> bool:
        return all(
            self._bits[pos // 8] & (1 << (pos % 8))
            for pos in self._positions(item)
        )

    def __repr__(self) -> str:
        return (
            f"BloomFilter(capacity={self.capacity}, "
            f"bits={self.m}, hashes={self.k})"
        )


# ── Levenshtein edit distance ─────────────────────────────────────────────────

def levenshtein(a: str, b: str) -> int:
    """
    Minimum edit distance (Wagner-Fischer algorithm).

    Counts the minimum number of single-character insertions, deletions, or
    substitutions needed to transform a into b.

    Time:  O(|a| * |b|)
    Space: O(min(|a|, |b|)) — single-row optimisation; we only keep the
           current and previous rows of the DP table rather than the full matrix.

    Used in the validator to detect evasion: a fact token like 'r1sk' has
    edit distance 1 from 'risk' and should be flagged.
    """
    if len(a) < len(b):
        a, b = b, a                     # ensure |a| >= |b| for space optimisation
    row = list(range(len(b) + 1))       # base case: distance from empty string
    for ch_a in a:
        prev, row[0] = row[0], row[0] + 1
        for j, ch_b in enumerate(b):
            prev, row[j + 1] = row[j + 1], min(
                row[j + 1] + 1,             # deletion
                row[j] + 1,                 # insertion
                prev + (ch_a != ch_b),      # substitution (0 if chars match)
            )
    return row[-1]
