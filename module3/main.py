"""Report real Module 1 authority traces against the existing Module 2 chain."""

from pathlib import Path
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from module3.tracer import _load_context, trace_action, trace_agent_authority
else:
    from .tracer import _load_context, trace_action, trace_agent_authority

from module2 import chain as blockchain


def print_trace(title: str, result: dict) -> None:
    print(f"\n=== TRACE: {title} ===")
    if result["chain"]:
        print("ROOT_AUTHORIZER")
        for hop in result["chain"]:
            print(f"    | {hop['permission']} [{hop['evidence_type']}]")
            print("    v")
            print(hop["to"])
        print()
        for number, hop in enumerate(result["chain"], start=1):
            time_status = (
                f" | valid_at_action_time={hop['valid_at_action_time']}"
                if hop.get("valid_at_action_time") is not None else ""
            )
            print(
                f"Hop {number} Proof : {'PASS' if hop['proof_verified'] else 'FAIL'} "
                f"| tx={hop['transaction_hash']} | block={hop['block_number']}{time_status}"
            )
            if hop.get("root_grant_proof_verified"):
                print("    Root grant action commitment: PASS")
    else:
        print("No rooted authority path")
    if evidence := result.get("revocation_evidence"):
        print(
            f"Revocation proof: {'PASS' if evidence['proof_verified'] else 'FAIL'} "
            f"| revoked_at={evidence['revoked_at']} "
            f"| tx={evidence['transaction_hash']} | block={evidence['block_number']}"
        )
    print(f"Verdict        : {result['verdict']}")
    print(f"Valid          : {result['valid']}")
    print(f"Reason         : {result['reason']}")
    print(f"Trace Latency  : {result['trace_latency_ms']:.2f} ms")


def run_demo() -> None:
    _, contract, _, deployment = blockchain.contract_context()
    context = _load_context()
    print(f"Existing AgentTrustRegistry: {contract.address} (chain {deployment['chain_id']})")
    print("Source: Module 1 records retained by Module 2; every real hop is checked on-chain")

    cases: list[tuple[str, dict, str, bool]] = []
    cases.append((
        "Agent_B / CREATE_AGENT",
        trace_agent_authority("Agent_B", "CREATE_AGENT"),
        "VALID_CHAIN", True,
    ))
    cases.append((
        "Agent_C / CREATE_AGENT (historical)",
        trace_agent_authority("Agent_C", "CREATE_AGENT"),
        "VALID_CHAIN", True,
    ))
    attack_expectations = (
        ("SELF_ESCALATION_ATTEMPT", "UNAUTHORIZED_ROOT"),
        ("UNAUTHORIZED_DELEGATION_ATTEMPT", "BROKEN_CHAIN"),
        ("POST_DECOMMISSION_ACTIVITY", "AUTHORITY_REVOKED_AT_TIME_OF_ACTION"),
    )
    for action_code, expected in attack_expectations:
        matches = [action for action in context.actions if action["action"] == action_code]
        if len(matches) != 1:
            raise AssertionError(f"Expected one real {action_code} entry; found {len(matches)}")
        cases.append((action_code, trace_action(matches[0]), expected, False))

    correct = 0
    invalid_attacks_correct = 0
    for index, (title, result, expected_verdict, expected_valid) in enumerate(cases):
        print_trace(title, result)
        matched = result["verdict"] == expected_verdict and result["valid"] is expected_valid
        correct += matched
        if index >= 2:
            invalid_attacks_correct += matched
    latencies = [result["trace_latency_ms"] for _, result, _, _ in cases]
    accuracy = correct / len(cases) * 100

    print("\n=== DELEGATION TRACE METRICS ===")
    print(f"Total Traces Tested: {len(cases)}")
    print(f"Correctly Classified: {correct}")
    print(f"Invalid Attacks Correctly Identified: {invalid_attacks_correct}/3")
    print(f"Delegation Trace Accuracy: {accuracy:.2f}%")
    print(f"Average Trace Latency: {sum(latencies) / len(latencies):.2f} ms")
    print(f"Worst-Case Trace Latency: {max(latencies):.2f} ms")

    assert len(cases) == 5 and correct == 5 and invalid_attacks_correct == 3
    assert all(hop["proof_verified"] for _, result, _, _ in cases[:2] for hop in result["chain"])
    assert cases[4][1]["revocation_evidence"]["proof_verified"]
    print("\n=== MODULE 3 COMPLETED SUCCESSFULLY ===")


if __name__ == "__main__":
    run_demo()
