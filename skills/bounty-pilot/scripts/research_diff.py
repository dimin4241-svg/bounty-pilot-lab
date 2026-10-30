#!/usr/bin/env python3
"""Passive, evidence-bounded semantic identity and cross-phase research.

No target code is executed. Source scans are lexical leads. Observation comparisons
use investigator-supplied expected equivalence; they are never exploit proofs.
Python 3.9+ and stdlib only.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

MAX_OBSERVATIONS = 1000
MAX_SOURCE_FILES = 4000
MAX_SOURCE_BYTES = 128 * 1024
MAX_FINDINGS = 200
MAX_QUORUM_SIGNERS = 128
CONTEXT_FIELDS = ("domain", "chain_id", "epoch", "nonce", "state_digest",
                  "attacker_permissions", "operation_id")
SOURCE_EXTENSIONS = {".sol", ".vy", ".rs", ".go", ".py", ".ts", ".tsx",
                     ".js", ".jsx", ".cpp", ".cc", ".c", ".h", ".hpp", ".move"}
EXCLUDE_PARTS = {"vendor", "node_modules", "dist", "build", "target",
                 "__pycache__", "test", "tests", "fixtures", "examples"}
GIT_OPTS = ("--no-optional-locks", "-c", "core.fsmonitor=false", "-c",
            "core.hooksPath=/dev/null", "-c", "core.pager=cat")
MAX_CUSTOM_CUES = 16
MAX_CUE_PATTERN = 200
CUE_KIND = re.compile(r"\A[a-z][a-z0-9_]{0,31}\Z")
# `\b` treats "_" as a word character, so \bcache_key\b misses build_cache_key and
# cache_key_prefix. These separators bound on alphanumerics only, so a cue inside a
# longer snake_case or camelCase identifier still matches.
_L = r"(?<![A-Za-z0-9])"
_R = r"(?![A-Za-z0-9])"
# Each family carries the multi-word camelCase spelling next to the snake_case one:
# (?i) alone bridges cacheKey/cache_key but never validateBlock/validate_block, so a
# cue set written in one convention reads a codebase in another as clean.
PATTERNS = (
    ("packed_dynamic",
     re.compile(r"\b(?:abi\.encodePacked|encodePacked|solidityPacked|encode_packed)\s*\("),
     "Compare tuple identity with packed ABI encoding; multiple dynamic arguments may be ambiguous.",
     False),
    ("cache_context",
     re.compile(r"(?i)" + _L + r"(?:cache_key|cachekey|proof_cache|proofcache|cache_hash"
                r"|cachehash|cache_id|cacheid)" + _R),
     "Check that cache identity includes all verification context and unambiguous framing.",
     False),
    ("cache_key_builder",
     re.compile(r"\b(?:key|prefix)[A-Z][A-Za-z0-9]*"),
     "Identifier shape only: check what this key or prefix is built from, and whether "
     "unnormalised caller input can reach it.", True),
    ("signature_quorum",
     re.compile(r"(?i)" + _L + r"(?:signer_count|signercount|signatures\.length"
                r"|signatures\.len|num_signers|numsigners|signer_threshold"
                r"|signerthreshold|quorum|quorum_size|quorumsize|threshold)" + _R),
     "Review whether quorum counts unique authenticated signers rather than signatures.",
     False),
    ("phase_boundary",
     re.compile(r"(?i)" + _L + r"(?:mempool|mem_pool|txpool|tx_pool|validate_block"
                r"|validateblock|sign_transaction|signtransaction|execute_job|executejob"
                r"|withdrawal_worker|withdrawalworker)" + _R),
     "Compare the admission policy, authorized payload, and execution decision.",
     False),
)


def compile_cues(extra=None):
    """Default families plus investigator cues as `kind=regex`; a bad cue fails closed.

    What a cache key, a quorum or a phase boundary is called is per project, so a zero
    from this scan is only as good as the vocabulary behind it. The report names the
    vocabulary that produced it.
    """
    cues = list(PATTERNS)
    if not extra:
        return cues
    if not isinstance(extra, (list, tuple)):
        raise ValueError("--cue must be repeatable kind=regex text")
    if len(extra) > MAX_CUSTOM_CUES:
        raise ValueError("at most %d --cue values" % MAX_CUSTOM_CUES)
    seen = set()
    for item in extra:
        if not isinstance(item, str) or "=" not in item:
            raise ValueError("--cue must be kind=regex, e.g. cache_context=keyCache\\w+")
        kind, _, expression = item.partition("=")
        kind = kind.strip()
        if not CUE_KIND.match(kind):
            raise ValueError("cue kind must be a short lowercase slug: " + kind[:32])
        if not expression or len(expression) > MAX_CUE_PATTERN:
            raise ValueError("cue regex for %s must be 1..%d characters" % (kind, MAX_CUE_PATTERN))
        if (kind, expression) in seen:
            raise ValueError("duplicate cue: " + kind)
        seen.add((kind, expression))
        try:
            compiled = re.compile(expression)
        except re.error as exc:
            raise ValueError("cue regex for %s does not compile: %s" % (kind, exc)) from exc
        cues.append((kind, compiled,
                     "Investigator-supplied cue; the same evidence burden applies.", False))
    return cues


def _text(value, name, limit=500):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(name + " must be nonempty short text")
    if any(ord(c) < 32 for c in value):
        raise ValueError(name + " contains control characters")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(name + " contains invalid Unicode") from exc
    return value


def _basis_text(value, name):
    if not isinstance(value, str) or len(value) > 500:
        raise ValueError(name + " must be short text or empty")
    if any(ord(c) < 32 for c in value):
        raise ValueError(name + " contains control characters")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(name + " contains invalid Unicode") from exc
    return value


def _json(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 2_000_000:
        raise ValueError("input must be a regular non-symlink JSON file under 2 MB")
    try:
        return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except RecursionError as exc:
        raise ValueError("input JSON nesting exceeds the parser limit") from exc


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("input JSON contains a duplicate object key")
        result[key] = value
    return result


def _fingerprint(value, label, limit=500):
    if value is None:
        return None
    text = _text(value, label, limit)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _encoded_bytes(value, label):
    if value is None:
        return None
    if (not isinstance(value, str) or
            not re.fullmatch(r"0x(?:[0-9a-fA-F]{2}){0,65536}", value)):
        raise ValueError(label + " must be bounded even-length 0x hex")
    return bytes.fromhex(value[2:])


def _report(mode, items, notes=()):
    return {"schema_version": 1, "mode": mode, "classification": "RESEARCH_LEADS",
            "leads": items[:MAX_FINDINGS], "candidate_count": len(items),
            "truncated": len(items) > MAX_FINDINGS, "notes": list(notes),
            "confirmed_vulnerabilities": 0,
            "notice": "Source and supplied observations are clues, not native PoCs, "
                      "authorization proof, exploitable reachability, or severity."}


def identity(data):
    """Compare supplied *semantic identities* against actual representation identifiers.

    'same' and 'different' are user-supplied assumptions, not our conclusions.
    """
    if (not isinstance(data, dict) or type(data.get("schema_version")) is not int
            or data["schema_version"] != 1):
        raise ValueError("identity input needs schema_version 1")
    pairs = data.get("pairs")
    if not isinstance(pairs, list) or len(pairs) > MAX_OBSERVATIONS:
        raise ValueError("pairs must be a bounded list")
    output, ids = [], set()
    for pos, p in enumerate(pairs):
        if not isinstance(p, dict):
            raise ValueError("pair must be an object")
        label = _text(p.get("id"), "id", 100)
        if label in ids:
            raise ValueError("pair IDs must be unique")
        ids.add(label)
        relation = p.get("expected_semantic_relation")
        if relation not in ("same", "different"):
            raise ValueError("expected_semantic_relation must be same or different")
        a, b = p.get("left"), p.get("right")
        if not isinstance(a, dict) or not isinstance(b, dict):
            raise ValueError("left and right must be objects")
        left = _text(a.get("identity_key"), "left.identity_key")
        right = _text(b.get("identity_key"), "right.identity_key")
        basis = _basis_text(p.get("equivalence_basis"), "equivalence_basis")
        signals = []
        collision = relation == "different" and left == right
        split = relation == "same" and left != right
        if collision:
            signals.append("DISTINCT_CONTEXT_SHARED_KEY")
        if split:
            signals.append("SAME_ACTION_DISTINCT_KEY")
        message_execution_mismatch = []
        side_fingerprints = {}
        encoded = {}
        side_context = {}
        encoded_raw = {}
        for side_name, side in (("left", a), ("right", b)):
            verified = _fingerprint(side.get("verified_message_fingerprint"),
                                    side_name + ".verified_message_fingerprint")
            executed = _fingerprint(side.get("executed_operation_fingerprint"),
                                    side_name + ".executed_operation_fingerprint")
            side_fingerprints[side_name] = {
                "verified_message": verified,
                "executed_operation": executed,
            }
            if verified is not None and executed is not None and verified != executed:
                message_execution_mismatch.append(side_name)
            raw = _encoded_bytes(side.get("encoded_payload_hex"),
                                 side_name + ".encoded_payload_hex")
            encoded_raw[side_name] = raw
            encoded[side_name] = (hashlib.sha256(raw).hexdigest() if raw is not None else None)
            side_context[side_name] = {
                field: _fingerprint(side.get(field), side_name + "." + field, 200)
                for field in CONTEXT_FIELDS
            }
        if (encoded_raw["left"] is not None and encoded_raw["right"] is not None
                and encoded_raw["left"] != encoded_raw["right"] and relation == "same"):
            signals.append("SEMANTICALLY_EQUIVALENT_DIFFERENT_BYTES")
        if (encoded_raw["left"] is not None and encoded_raw["right"] is not None
                and encoded_raw["left"] == encoded_raw["right"] and relation == "different"):
            signals.append("DISTINCT_SEMANTICS_IDENTICAL_BYTES")
        if message_execution_mismatch:
            signals.append("VERIFIED_MESSAGE_EXECUTION_MISMATCH")
        if signals:
            output.append({
                "id": label, "index": pos,
                "signal": signals[0], "signals": signals,
                "identity_key_sha256": [hashlib.sha256(x.encode("utf-8")).hexdigest()
                                        for x in (left, right)],
                "expected_semantic_relation": relation,
                "identity_keys_equal": left == right,
                "encoded_payload_sha256": encoded,
                "encoded_payloads_equal": (None if encoded_raw["left"] is None or
                                           encoded_raw["right"] is None else
                                           encoded_raw["left"] == encoded_raw["right"]),
                "verified_and_executed_fingerprints": side_fingerprints,
                "message_execution_mismatch_sides": message_execution_mismatch,
                "security_context_fingerprints": side_context,
                "equivalence_basis": basis,
                "basis_status": "PROVIDED" if basis.strip() else "MISSING",
                "classification": "NEEDS_EVIDENCE",
                "next_experiment": "Verify the stated equivalence independently using native "
                                   "decoders/verifiers on an owned local fixture; compare "
                                   "candidate against a normal negative control.",
                "falsifier": "The two inputs are not semantically equivalent, the cache/replay "
                             "key is intentionally scoped, or authorization is independently checked.",
            })
    return _report("semantic-identity", output,
                   ["A shared key or distinct representation is not automatically unsafe. "
                    "Digest algorithms and binary encodings are not emulated. Optional verified-message, "
                    "executed-operation, and domain fields are investigator-supplied fingerprints."])


def phases(data):
    """Find contradictory stage decisions only within a declared comparable policy."""
    if (not isinstance(data, dict) or type(data.get("schema_version")) is not int
            or data["schema_version"] != 1):
        raise ValueError("phase input needs schema_version 1")
    cases = data.get("cases")
    if not isinstance(cases, list) or len(cases) > MAX_OBSERVATIONS:
        raise ValueError("cases must be a bounded list")
    signals, non_comparable, ids = [], [], set()
    for idx, case in enumerate(cases):
        if not isinstance(case, dict):
            raise ValueError("case must be an object")
        ident = _text(case.get("id"), "case.id", 100)
        if ident in ids:
            raise ValueError("case IDs must be unique")
        ids.add(ident)
        basis = _basis_text(case.get("equivalence_basis", ""), "equivalence_basis")
        declared_comparable = case.get("same_policy_expected") is True and bool(basis.strip())
        state_transition_expected = case.get("state_transition_expected", False)
        if type(state_transition_expected) is not bool:
            raise ValueError("state_transition_expected must be boolean")
        required_context = case.get("required_context_fields", [])
        if (not isinstance(required_context, list) or len(required_context) > len(CONTEXT_FIELDS)
                or any(not isinstance(x, str) or x not in CONTEXT_FIELDS
                       for x in required_context)
                or len(set(required_context)) != len(required_context)):
            raise ValueError("required_context_fields must be unique known context field names")
        stages = case.get("stages")
        if not isinstance(stages, list) or not 2 <= len(stages) <= 20:
            raise ValueError("stages must contain 2..20 objects")
        names, normalized = set(), []
        for stage_index, step in enumerate(stages):
            if not isinstance(step, dict):
                raise ValueError("stage must be an object")
            name = _text(step.get("name"), "stage.name", 100)
            if name in names:
                raise ValueError("stage name repeated")
            names.add(name)
            decision = step.get("decision")
            if decision not in ("allow", "deny", "unknown"):
                raise ValueError("decision must be allow, deny, or unknown")
            payload = step.get("payload_digest")
            if payload is not None:
                _text(payload, "payload_digest", 150)
            policy = step.get("policy_id")
            if policy is not None:
                _text(policy, "policy_id", 150)
            normalized.append({
                "order_index": stage_index, "name": name, "decision": decision,
                "payload_digest_fingerprint": hashlib.sha256(
                    payload.encode("utf-8")).hexdigest() if payload is not None else None,
                "policy_id_fingerprint": hashlib.sha256(
                    policy.encode("utf-8")).hexdigest() if policy is not None else None,
                "context_fingerprints": {
                    field: _fingerprint(step.get(field), "stage." + field, 200)
                    for field in CONTEXT_FIELDS
                },
            })
        known = {step["decision"] for step in normalized if step["decision"] != "unknown"}
        digests = {step["payload_digest_fingerprint"] for step in normalized
                   if step["payload_digest_fingerprint"] is not None}
        policies = {step["policy_id_fingerprint"] for step in normalized
                    if step["policy_id_fingerprint"] is not None}
        types, blockers, context_observations = [], [], []
        if not declared_comparable:
            blockers.append("NO_EQUIVALENCE_BASIS")
        if len(known) > 1:
            types.append("DECISION_DIVERGENCE")
        if len(digests) > 1:
            types.append("PAYLOAD_DRIFT")
        if len(policies) > 1:
            types.append("POLICY_VERSION_DRIFT")
            blockers.append("POLICY_VERSION_MISMATCH")
        policy_presence = [step["policy_id_fingerprint"] is not None for step in normalized]
        if not any(policy_presence):
            blockers.append("MISSING_POLICY_CONTEXT")
        elif not all(policy_presence):
            blockers.append("INCOMPLETE_POLICY_CONTEXT")
        for field in CONTEXT_FIELDS:
            values = [step["context_fingerprints"][field] for step in normalized]
            present = [value for value in values if value is not None]
            if field in required_context and len(present) != len(values):
                blockers.append("MISSING_" + field.upper() + "_CONTEXT")
            if present and len(present) != len(values):
                blockers.append("INCOMPLETE_" + field.upper() + "_CONTEXT")
            if len(set(present)) > 1:
                if field == "state_digest" and state_transition_expected:
                    context_observations.append("EXPECTED_STATE_TRANSITION")
                    blockers.append("STATE_TRANSITION_CONTEXT")
                elif field == "state_digest":
                    types.append("STATE_CONTEXT_DRIFT")
                    blockers.append("STATE_CONTEXT_MISMATCH")
                else:
                    types.append(field.upper() + "_DRIFT")
                    blockers.append(field.upper() + "_MISMATCH")
        if types or blockers:
            blockers = list(dict.fromkeys(blockers))
            observation = {
                "id": ident, "index": idx, "signals": types,
                "comparable": declared_comparable and not blockers, "stages": normalized,
                "context_observations": context_observations,
                "comparison_blockers": blockers,
                "comparison_blocker": blockers[0] if blockers else None,
                "equivalence_basis": basis, "classification": "NEEDS_EVIDENCE",
                "next_experiment": "Pin the same request, policy epoch and authorized input; "
                                   "run each native stage locally with a paired normal control.",
                "falsifier": "Distinct policy versions, mutable request context, or intentionally "
                             "different admission/execution requirements explain the difference.",
            }
            if types:
                signals.append(observation)
            else:
                observation["classification"] = "NON_COMPARABLE_OBSERVATION"
                non_comparable.append(observation)
    report = _report("cross-phase", signals,
                   ["Comparability requires same_policy_expected=true plus a written basis. "
                    "Order is preserved. Chain, domain, epoch, nonce, state and attacker permissions "
                    "are fingerprinted; missing or changed context blocks comparability. "
                    "Even comparable divergences are hypotheses until native reproduction."])
    report["non_comparable_cases"] = non_comparable
    report["non_comparable_count"] = len(non_comparable)
    return report


def quorum(data):
    """Check supplied native-recovered signer IDs against unique quorum requirements.

    The tool does not verify signatures or authorize a signer. Candidate/control observations
    must come from the same local verifier and policy context.
    """
    if (not isinstance(data, dict) or type(data.get("schema_version")) is not int
            or data["schema_version"] != 1):
        raise ValueError("quorum input needs schema_version 1")
    cases = data.get("cases")
    if not isinstance(cases, list) or len(cases) > MAX_OBSERVATIONS:
        raise ValueError("cases must be a bounded list")
    ids, pairs = set(), {}
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise ValueError("quorum case must be an object")
        ident = _text(case.get("id"), "case.id", 100)
        if ident in ids:
            raise ValueError("case IDs must be unique")
        ids.add(ident)
        pair_id = _text(case.get("pair_id"), "pair_id", 100)
        role = case.get("role")
        if role not in ("candidate", "negative-control"):
            raise ValueError("role must be candidate or negative-control")
        if role in pairs.setdefault(pair_id, {}):
            raise ValueError("each pair needs one candidate and one negative-control")
        threshold = case.get("threshold")
        if type(threshold) is not int or not 1 <= threshold <= MAX_QUORUM_SIGNERS:
            raise ValueError("threshold must be between 1 and 128")
        allowed = case.get("authorized_signers")
        signers = case.get("authenticated_signers")
        if (not isinstance(allowed, list) or not 1 <= len(allowed) <= MAX_QUORUM_SIGNERS
                or not isinstance(signers, list) or len(signers) > MAX_QUORUM_SIGNERS):
            raise ValueError("authorized_signers and authenticated_signers must be bounded lists")
        allowed = [_text(item, "authorized_signer", 200) for item in allowed]
        signers = [_text(item, "authenticated_signer", 200) for item in signers]
        if len(set(allowed)) != len(allowed):
            raise ValueError("authorized_signers must be unique")
        context = case.get("context", {})
        if not isinstance(context, dict):
            raise ValueError("context must be an object")
        if any(key not in set(CONTEXT_FIELDS) | {"policy_id"} for key in context):
            raise ValueError("context has an unknown security field")
        context_fingerprints = {
            field: _fingerprint(value, "context." + field, 200)
            for field, value in context.items()
        }
        row = {"id": ident, "index": index, "role": role, "threshold": threshold,
               "authorized": allowed, "signers": signers,
               "context_fingerprints": context_fingerprints}
        pairs[pair_id][role] = row
    leads = []
    for pair_id, pair in sorted(pairs.items()):
        if set(pair) != {"candidate", "negative-control"}:
            raise ValueError("each quorum pair requires candidate and negative-control cases")
        candidate, control = pair["candidate"], pair["negative-control"]
        if (candidate["threshold"] != control["threshold"] or
                set(candidate["authorized"]) != set(control["authorized"])):
            raise ValueError("candidate and control must use the same threshold and authorized signer set")
        if (set(candidate["context_fingerprints"]) != set(control["context_fingerprints"])
                or candidate["context_fingerprints"] != control["context_fingerprints"]):
            raise ValueError("candidate and control must use the same security context and policy")
        threshold = candidate["threshold"]
        authorized = set(candidate["authorized"])
        control_unique = len(set(control["signers"]) & authorized)
        if control_unique < threshold:
            raise ValueError("negative control must contain a valid unique signer quorum")
        candidate_unique = len(set(candidate["signers"]) & authorized)
        if len(candidate["signers"]) >= threshold and candidate_unique < threshold:
            leads.append({
                "id": candidate["id"], "pair_id_fingerprint": hashlib.sha256(
                    pair_id.encode("utf-8")).hexdigest(),
                "signal": "INSUFFICIENT_UNIQUE_AUTHORIZED_SIGNERS",
                "threshold": threshold,
                "authenticated_signature_count": len(candidate["signers"]),
                "unique_authorized_signer_count": candidate_unique,
                "candidate_signer_fingerprints": sorted({hashlib.sha256(x.encode("utf-8")).hexdigest()
                                                          for x in candidate["signers"]}),
                "control_signer_fingerprints": sorted({hashlib.sha256(x.encode("utf-8")).hexdigest()
                                                        for x in control["signers"]}),
                "context_fingerprints": candidate["context_fingerprints"],
                "classification": "SUPPLIED_OBSERVATION_LEAD",
                "next_experiment": "Reproduce using the target's native signature recovery and "
                                   "authorization checks; prove duplicate signatures count in the "
                                   "actual quorum path and keep the paired valid-signers control passing.",
                "falsifier": "The target counts unique authorized signers after cryptographic "
                             "verification, or duplicate signatures never reach a quorum decision.",
            })
    return _report("signer-quorum", leads,
                   ["Signer IDs are assumed to come from a local native verifier; this tool does "
                    "not verify signatures, keys, authorization, reachability, or impact.",
                    "Every candidate is paired with a valid unique-signer negative control."])



def _hex_fields(value, label):
    """Decode only explicit bounded bytes fields; never infer Solidity ABI types."""
    if not isinstance(value, list) or not 2 <= len(value) <= 16:
        raise ValueError(label + " needs 2..16 explicit byte fields")
    output = []
    for i, field in enumerate(value):
        if (not isinstance(field, str) or not field.startswith("0x")
                or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2}){0,4096}", field)):
            raise ValueError(label + "[%d] must be bounded even-length 0x hex" % i)
        output.append(bytes.fromhex(field[2:]))
    if sum(len(x) for x in output) > 4096:
        raise ValueError(label + " exceeds 4096 total bytes")
    return output


def byte_tuple(data):
    """Executable byte-framing counterexample on supplied *owned* synthetic tuples.

    Demonstrates injectivity of plain concatenation against length-prefixed framing.
    This is NOT a full Solidity abi.encodePacked encoder or real target PoC.
    """
    if (not isinstance(data, dict) or type(data.get("schema_version")) is not int
            or data["schema_version"] != 1):
        raise ValueError("byte-tuple input needs schema_version 1")
    pairs = data.get("pairs")
    if not isinstance(pairs, list) or len(pairs) > 200:
        raise ValueError("pairs must be a list of at most 200")
    leads, ids = [], set()
    controls = 0
    for index, row in enumerate(pairs):
        if not isinstance(row, dict):
            raise ValueError("pair must be an object")
        ident = _text(row.get("id"), "id", 100)
        if ident in ids:
            raise ValueError("pair IDs must be unique")
        ids.add(ident)
        left = _hex_fields(row.get("left_fields"), "left_fields")
        right = _hex_fields(row.get("right_fields"), "right_fields")
        if len(left) != len(right):
            raise ValueError("field count differs across tuple pair")
        unpacked_distinct = left != right
        packed_left, packed_right = b"".join(left), b"".join(right)
        # Explicit length framing prevents ambiguity for sequences of byte fields.
        framed = lambda fields: b"".join(len(x).to_bytes(4, "big") + x
                                        for x in fields)
        control_distinct = framed(left) != framed(right)
        if not control_distinct and unpacked_distinct:
            raise AssertionError("length framing did not preserve tuple distinction")
        if unpacked_distinct and packed_left == packed_right:
            leads.append({
                "id": ident, "index": index, "signal": "UNFRAMED_TUPLE_COLLISION",
                "field_count": len(left),
                "left_lengths": [len(x) for x in left],
                "right_lengths": [len(x) for x in right],
                "unframed_sha256": hashlib.sha256(packed_left).hexdigest(),
                "framed_sha256": [hashlib.sha256(framed(f)).hexdigest()
                                 for f in (left, right)],
                "framed_negative_control": "DISTINCT",
                "classification": "SYNTHETIC_COUNTEREXAMPLE",
                "next_experiment": "Show that a target's *actual* dynamic-field encoding "
                                   "and replay/cache verification consumes this ambiguous byte "
                                   "sequence. Run candidate and control with native codec, "
                                   "explicitly scoped caller and pinned revision.",
                "falsifier": "The real target uses fixed-width typed fields, length framing, "
                             "an independent semantic check, or no security-relevant hash key.",
            })
        else:
            controls += 1
    result = _report("byte-tuple", leads, [
        "Actual byte computations executed here; target-specific vulnerability and "
        "the semantics of those fields remain UNVERIFIED.",
        "Generic raw-byte concatenation only. Solidity ABI packed encoding of "
        "fixed-width types, arrays, strings and nested tuples needs a native codec."
    ])
    result["non_collision_pairs"] = controls
    return result


def source_scan(repo, scope_prefixes, cues=None):
    """Tracked local source only, with symlink/size/extension bounds and safe git config."""
    if not isinstance(scope_prefixes, (list, tuple)) or not scope_prefixes:
        raise ValueError("scan requires explicit --scope path prefixes")
    patterns = compile_cues(cues)
    vocabulary = {
        "cue_kinds": sorted({cue[0] for cue in patterns}),
        "default_cue_kinds": sorted({cue[0] for cue in PATTERNS}),
        "shape_only_cue_kinds": sorted({cue[0] for cue in patterns if cue[3]}),
        "custom_cues": max(0, len(patterns) - len(PATTERNS)),
    }
    for prefix in scope_prefixes:
        if (not isinstance(prefix, str) or not prefix or prefix.startswith("/")
                or ".." in Path(prefix).parts or chr(0) in prefix
                or "\\" in prefix or prefix.rstrip("/") in (".", "")):
            raise ValueError("scope must be a relative checkout path prefix")
    root = Path(repo).resolve()
    if not (root / ".git").exists():
        raise ValueError("scan requires a local git checkout")
    p = subprocess.run(["git", *GIT_OPTS, "-C", str(root), "ls-files", "-z"],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=25, check=True, env=dict(os.environ, GIT_TERMINAL_PROMPT="0"))
    names = sorted(x for x in p.stdout.decode("utf-8", "replace").split("\0") if x)
    scoped = [name for name in names
              if any(name == prefix.rstrip("/") or
                     name.startswith(prefix.rstrip("/") + "/")
                     for prefix in scope_prefixes)]
    found = []
    skipped = {"non_source": 0, "oversized": 0, "unreadable": 0}
    scanned = 0
    for name in scoped[:MAX_SOURCE_FILES]:
        path = Path(name)
        if path.suffix.lower() not in SOURCE_EXTENSIONS or EXCLUDE_PARTS.intersection(path.parts):
            skipped["non_source"] += 1
            continue
        target = root / path
        try:
            if target.is_symlink() or not target.resolve().is_relative_to(root):
                skipped["unreadable"] += 1
                continue
            if not target.is_file() or target.stat().st_size > MAX_SOURCE_BYTES:
                skipped["oversized"] += 1
                continue
            lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            skipped["unreadable"] += 1
            continue
        scanned += 1
        shape_leads = {}
        for number, line in enumerate(lines, 1):
            for kind, pattern, question, shape_only in patterns:
                if not pattern.search(line):
                    continue
                if shape_only:
                    # One lead per file: a shape cue matches identifiers, so reporting
                    # every line buries the precise families under one key-builder file.
                    lead = shape_leads.get(kind)
                    if lead is not None:
                        lead["matched_lines"] += 1
                        continue
                    lead = {"signal": kind, "path": name, "line": number,
                            "classification": "LEXICAL_LEAD", "shape_only": True,
                            "matched_lines": 1, "review_question": question,
                            "next_experiment": "Trace actual data dependencies and native "
                                               "caller/validation behavior with a control."}
                    shape_leads[kind] = lead
                    found.append(lead)
                else:
                    found.append({"signal": kind, "path": name, "line": number,
                                  "classification": "LEXICAL_LEAD", "shape_only": False,
                                  "review_question": question,
                                  "next_experiment": "Trace actual data dependencies and native "
                                                     "caller/validation behavior with a control."})
                if len(found) >= MAX_FINDINGS:
                        return dict(_report("source-scan", found,
                                           ["Scan capped at 200 lexical signals."]),
                                    truncated=True,
                                    scanned_files=scanned, skipped=skipped,
                                    files_over_cap=max(0, len(scoped) - MAX_SOURCE_FILES),
                                    in_scope_tracked_files=len(scoped),
                                    **vocabulary)
    notes = (["No tracked source file matched the declared scope; not a clean scan."]
             if not scoped or scanned == 0 else [])
    if scanned and not found:
        notes.append("No cue matched. What a cache key, quorum or phase boundary is "
                     "called is per project: this zero only covers the cue kinds listed "
                     "in cue_kinds. Calibrate with --cue against a known site before "
                     "reading it as a clean scan.")
    return dict(_report("source-scan", found, notes),
                scanned_files=scanned, skipped=skipped,
                in_scope_tracked_files=len(scoped),
                files_over_cap=max(0, len(scoped) - MAX_SOURCE_FILES),
                **vocabulary)


def main(argv=None):
    cli = argparse.ArgumentParser(description=__doc__)
    subs = cli.add_subparsers(dest="command", required=True)
    for action in ("identity", "phases", "byte-tuple", "quorum"):
        sub = subs.add_parser(action)
        sub.add_argument("--input", required=True)
    scan = subs.add_parser("scan")
    scan.add_argument("--repo", required=True)
    scan.add_argument("--scope", action="append", required=True,
                      help="repeatable in-scope relative path prefix; never scan all by default")
    scan.add_argument("--cue", action="append", default=None,
                      help="repeatable kind=regex cue in the project's own vocabulary, "
                           "e.g. cache_context=keyCache\\w+")
    args = cli.parse_args(argv)
    try:
        if args.command == "identity":
            result = identity(_json(args.input))
        elif args.command == "phases":
            result = phases(_json(args.input))
        elif args.command == "byte-tuple":
            result = byte_tuple(_json(args.input))
        elif args.command == "quorum":
            result = quorum(_json(args.input))
        else:
            result = source_scan(args.repo, args.scope, args.cue)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
