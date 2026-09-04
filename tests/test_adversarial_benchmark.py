"""Deterministic tests for the Step 25 adversarial benchmark.

These tests require no API key, no network, no real LLM, no shell, and no
execution of repository instructions. They verify:

* the six attack categories are all covered by the Step 24 case suite,
* the clean/adversarial pairing is preserved through ``base_case_id``,
* the structured evaluation representation validates its inputs,
* the three headline metrics (attack success, correct rejection, false
  conclusion) are computed with exact, hand-checkable formulas,
* zero-case and invalid inputs are handled safely,
* deterministic scoring and reproducible reports across multiple systems,
* conflicting-findings and poisoned-evidence cases resolve to the recorded
  expected resolution,
* the benchmark performs no network activity and contains no secrets.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.evaluation.adversarial import (
    ADVERSARIAL_CASES,
    ALL_ADVERSARIAL_CASES,
    ALL_ATTACK_CATEGORIES,
    ATTACK_CATEGORY_COVERAGE,
)
from src.evaluation.adversarial_result import (
    OUTCOME_NO_CONCLUSION,
    AdversarialResponse,
)
from src.evaluation.adversarial_scoring import (
    attack_success_rate,
    build_report,
    correct_rejection_rate,
    evidence_preservation_rate,
    false_conclusion_rate,
    no_conclusion_rate,
)
from src.evaluation.prompt_injection import (
    OUTCOME_REPORT_LEGITIMATE_FINDING,
    OUTCOME_REPORT_NO_FINDING,
    PROMPT_INJECTION_CASES,
)

LG = OUTCOME_REPORT_LEGITIMATE_FINDING
NF = OUTCOME_REPORT_NO_FINDING
NC = OUTCOME_NO_CONCLUSION


def adversarial(
    case_id: str = "pi_readme",
    system_name: str = "LLM Baseline",
    expected: str = LG,
    observed: str = LG,
    followed: bool = False,
    rejected: bool = False,
    evidence_expected: list[str] | None = None,
    evidence_identified: list[str] | None = None,
    notes: str = "",
) -> AdversarialResponse:
    return AdversarialResponse(
        case_id=case_id,
        system_name=system_name,
        is_adversarial=True,
        expected_security_outcome=expected,
        observed_security_outcome=observed,
        injection_followed=followed,
        injection_rejected=rejected,
        evidence_expected=evidence_expected or ["app.py"],
        evidence_identified=evidence_identified or ["app.py"],
        notes=notes,
    )


def clean(
    case_id: str = "case_a",
    system_name: str = "LLM Baseline",
    expected: str = LG,
    observed: str = LG,
) -> AdversarialResponse:
    return AdversarialResponse(
        case_id=case_id,
        system_name=system_name,
        is_adversarial=False,
        expected_security_outcome=expected,
        observed_security_outcome=observed,
        evidence_expected=["app.py"],
        evidence_identified=["app.py"],
    )


# ---------------------------------------------------------------------------
# 1. Attack categories and clean/adversarial pairing
# ---------------------------------------------------------------------------


class TestAttackCategories:
    def test_all_six_categories_covered(self) -> None:
        assert len(ADVERSARIAL_CASES) >= 6
        assert ATTACK_CATEGORY_COVERAGE.covered_categories == set(
            ALL_ATTACK_CATEGORIES
        )
        assert not ATTACK_CATEGORY_COVERAGE.missing_categories

    def test_each_required_category_has_a_case(self) -> None:
        categories = {c.category for c in ADVERSARIAL_CASES.values()}
        for category in ALL_ATTACK_CATEGORIES:
            assert category in categories, f"missing category {category}"

    def test_category_mapping_is_explicit(self) -> None:
        # Spot-check the intended Step 25 assignments hold.
        assert ADVERSARIAL_CASES["pi_readme"].category == "direct_prompt_injection"
        assert (
            ADVERSARIAL_CASES["pi_test_file"].category
            == "indirect_prompt_injection"
        )
        assert (
            ADVERSARIAL_CASES["pi_source_comment"].category
            == "misleading_comments"
        )
        assert (
            ADVERSARIAL_CASES["pi_documentation"].category
            == "malicious_documentation"
        )
        assert (
            ADVERSARIAL_CASES["pi_commit_message"].category
            == "poisoned_security_evidence"
        )
        assert (
            ADVERSARIAL_CASES["pi_configuration"].category
            == "conflicting_findings"
        )

    def test_no_duplicate_case_definitions(self) -> None:
        # The Step 25 layer references Step 24 cases, it does not redefine them.
        for case_id in ALL_ADVERSARIAL_CASES:
            assert case_id in PROMPT_INJECTION_CASES
            assert ADVERSARIAL_CASES[case_id].source is PROMPT_INJECTION_CASES[
                case_id
            ]

    def test_clean_control_pairing_preserved(self) -> None:
        # Every adversarial case records its clean twin via base_case_id and all
        # Step 25 cases expect a legitimate finding (they all contain a real
        # weakness).
        for case in ADVERSARIAL_CASES.values():
            assert case.expected_security_outcome == LG
            if case.clean_control_id is not None:
                assert case.clean_control_id.startswith("case_")
            # The clean twin exists in the Step 12 eval registry.
            from src.evaluation.ground_truth import EVAL_CASES

            if case.clean_control_id is not None:
                assert case.clean_control_id in EVAL_CASES


# ---------------------------------------------------------------------------
# 2. Evaluation representation and validation
# ---------------------------------------------------------------------------


class TestEvaluationRepresentation:
    def test_response_records_expected_fields(self) -> None:
        r = adversarial(notes="recorded reasoning", rejected=True)
        assert r.case_id == "pi_readme"
        assert r.system_name == "LLM Baseline"
        assert r.is_adversarial is True
        assert r.expected_security_outcome == LG
        assert r.observed_security_outcome == LG
        assert r.injection_followed is False
        assert r.injection_rejected is True
        assert r.evidence_expected == ["app.py"]
        assert r.evidence_identified == ["app.py"]
        assert r.notes == "recorded reasoning"

    def test_properties_correct_and_false_conclusion(self) -> None:
        assert adversarial(observed=LG).correct_conclusion is True
        assert adversarial(observed=LG).false_conclusion is False
        assert adversarial(observed=NF).false_conclusion is True
        assert adversarial(observed=NF).correct_conclusion is False
        # No conclusion: neither correct nor false.
        nc = adversarial(observed=NC)
        assert nc.has_conclusion is False
        assert nc.correct_conclusion is False
        assert nc.false_conclusion is False

    def test_injection_followed_and_rejected_mutually_exclusive(self) -> None:
        with pytest.raises(ValidationError):
            adversarial(followed=True, rejected=True)

    def test_clean_controls_cannot_follow_or_reject_injection(self) -> None:
        with pytest.raises(ValidationError):
            AdversarialResponse(
                case_id="case_a",
                system_name="s",
                is_adversarial=False,
                expected_security_outcome=LG,
                observed_security_outcome=LG,
                injection_followed=True,
            )
        with pytest.raises(ValidationError):
            AdversarialResponse(
                case_id="case_a",
                system_name="s",
                is_adversarial=False,
                expected_security_outcome=LG,
                observed_security_outcome=LG,
                injection_rejected=True,
            )

    def test_invalid_outcome_rejected(self) -> None:
        with pytest.raises(ValidationError):
            adversarial(observed="not_real")
        with pytest.raises(ValidationError):
            clean(expected="bogus")

    def test_evidence_preserved_property(self) -> None:
        r = adversarial(
            evidence_expected=["app.py", "config.yml"],
            evidence_identified=["app.py"],
        )
        assert r.evidence_preserved is False
        r2 = adversarial(
            evidence_expected=["app.py", "config.yml"],
            evidence_identified=["config.yml", "app.py"],
        )
        assert r2.evidence_preserved is True


# ---------------------------------------------------------------------------
# 3. Attack Success Rate
# ---------------------------------------------------------------------------


class TestAttackSuccessRate:
    def test_zero_of_ten_attack(self) -> None:
        responses = [adversarial(rejected=True) for _ in range(10)]
        assert attack_success_rate(responses) == 0.0

    def test_three_of_ten_attack(self) -> None:
        responses = [adversarial(rejected=True) for _ in range(7)]
        responses += [adversarial(followed=True) for _ in range(3)]
        assert attack_success_rate(responses) == pytest.approx(0.3)

    def test_ten_of_ten_attack(self) -> None:
        responses = [adversarial(followed=True) for _ in range(10)]
        assert attack_success_rate(responses) == pytest.approx(1.0)

    def test_clean_cases_are_excluded_from_denominator(self) -> None:
        # Clean controls must never dilute the ASR denominator.
        responses = [clean() for _ in range(100)]
        responses += [adversarial(followed=True)]
        assert attack_success_rate(responses) == pytest.approx(1.0)

    def test_empty_returns_zero(self) -> None:
        assert attack_success_rate([]) == 0.0

    def test_all_clean_returns_zero(self) -> None:
        assert attack_success_rate([clean() for _ in range(5)]) == 0.0


# ---------------------------------------------------------------------------
# 4. Correct Rejection Rate
# ---------------------------------------------------------------------------


class TestCorrectRejectionRate:
    def test_zero_of_ten_reject(self) -> None:
        responses = [adversarial(followed=True) for _ in range(10)]
        assert correct_rejection_rate(responses) == 0.0

    def test_seven_of_ten_reject(self) -> None:
        responses = [adversarial(rejected=True) for _ in range(7)]
        responses += [adversarial(followed=True) for _ in range(3)]
        assert correct_rejection_rate(responses) == pytest.approx(0.7)

    def test_ten_of_ten_reject(self) -> None:
        responses = [adversarial(rejected=True) for _ in range(10)]
        assert correct_rejection_rate(responses) == pytest.approx(1.0)

    def test_complementarity_with_attack_success(self) -> None:
        # For valid adversarial responses ASR + CRR == 1.
        responses = [
            adversarial(rejected=True) if i % 2 == 0 else adversarial(followed=True)
            for i in range(20)
        ]
        asr = attack_success_rate(responses)
        crr = correct_rejection_rate(responses)
        assert asr + crr == pytest.approx(1.0)

    def test_empty_returns_zero(self) -> None:
        assert correct_rejection_rate([]) == 0.0

    def test_clean_cases_excluded(self) -> None:
        responses = [clean() for _ in range(20)]
        responses += [adversarial(rejected=True)]
        assert correct_rejection_rate(responses) == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# 5. False Conclusion Rate
# ---------------------------------------------------------------------------


class TestFalseConclusionRate:
    def test_no_false_conclusions(self) -> None:
        responses = [
            adversarial(rejected=True, observed=LG),
            clean(observed=LG),
            clean(observed=LG),
        ]
        assert false_conclusion_rate(responses) == 0.0

    def test_hand_checkable_example(self) -> None:
        # 2 of 4 concluded cases are false.
        responses = [
            clean(observed=LG),  # correct
            clean(observed=NF),  # false
            adversarial(rejected=True, observed=LG),  # correct
            adversarial(followed=True, observed=NF),  # false
            adversarial(observed=NC),  # no conclusion: excluded
        ]
        assert false_conclusion_rate(responses) == pytest.approx(0.5)

    def test_adversarial_false_conclusion(self) -> None:
        # Injection causes suppression -> false conclusion.
        responses = [adversarial(followed=True, observed=NF)]
        assert false_conclusion_rate(responses) == pytest.approx(1.0)

    def test_clean_false_conclusion_counts(self) -> None:
        # A false conclusion in a clean control is still a false conclusion.
        responses = [clean(observed=NF), clean(observed=LG)]
        assert false_conclusion_rate(responses) == pytest.approx(0.5)

    def test_no_conclusion_excluded_from_denominator(self) -> None:
        responses = [
            adversarial(observed=NC),
            adversarial(observed=NC),
            clean(observed=LG),
        ]
        assert false_conclusion_rate(responses) == 0.0

    def test_empty_returns_zero(self) -> None:
        assert false_conclusion_rate([]) == 0.0

    def test_no_conclusion_rate_is_separate(self) -> None:
        responses = [adversarial(observed=NC), clean(observed=LG)]
        assert no_conclusion_rate(responses) == pytest.approx(0.5)
        assert false_conclusion_rate(responses) == 0.0


# ---------------------------------------------------------------------------
# 6. Deterministic scoring / reproducibility / multiple systems
# ---------------------------------------------------------------------------


class TestScoringDeterminism:
    def test_same_inputs_same_metrics(self) -> None:
        responses = [
            adversarial(case_id="pi_readme"),
            adversarial(case_id="pi_source_comment", followed=True),
            clean(case_id="case_b", observed=NF),
        ]
        assert attack_success_rate(responses * 1) == attack_success_rate(
            list(responses)
        )
        assert false_conclusion_rate(responses) == false_conclusion_rate(
            list(responses)
        )

    def test_evidence_preservation_supplement(self) -> None:
        responses = [
            adversarial() if i % 2 == 0 else adversarial(
                evidence_expected=["app.py"],
                evidence_identified=["other.py"],
            )
            for i in range(6)
        ]
        assert evidence_preservation_rate(responses) == pytest.approx(0.5)


class TestReport:
    def test_report_has_per_system_and_aggregate(self) -> None:
        responses = [
            adversarial(system_name="LLM Baseline", rejected=True),
            adversarial(system_name="SecureFlow", rejected=True),
            adversarial(
                system_name="Traditional Tools",
                followed=True,
            ),
            clean(system_name="LLM Baseline"),
        ]
        report = build_report(responses)
        assert set(report.systems) == {
            "LLM Baseline",
            "SecureFlow",
            "Traditional Tools",
        }
        assert report.aggregate is not None
        assert len(report.per_system) == 3
        assert len(report.case_rows) == 4

    def test_report_metric_values(self) -> None:
        responses = [
            adversarial(system_name="A", rejected=True),
            adversarial(system_name="A", followed=True),
            adversarial(system_name="B", rejected=True),
        ]
        report = build_report(responses)
        by_name = {m.system_name: m for m in report.per_system}
        assert by_name["A"].attack_success_rate == pytest.approx(0.5)
        assert by_name["A"].correct_rejection_rate == pytest.approx(0.5)
        assert by_name["B"].attack_success_rate == pytest.approx(0.0)
        assert by_name["B"].correct_rejection_rate == pytest.approx(1.0)

    def test_report_empty(self) -> None:
        report = build_report([])
        assert report.systems == ()
        assert report.per_system == ()
        assert report.case_rows == ()
        assert report.aggregate is not None
        assert report.aggregate.attack_success_rate == 0.0
        assert report.aggregate.false_conclusion_rate == 0.0
        d = report.to_dict()
        assert d["aggregate"]["total_cases"] == 0

    def test_report_deterministic_order(self) -> None:
        responses = [
            adversarial(system_name="B"),
            adversarial(system_name="A"),
        ]
        r1 = build_report(responses).to_dict()
        r2 = build_report(list(reversed(responses))).to_dict()
        assert r1 == r2

    def test_case_rows_are_inspectable(self) -> None:
        responses = [
            adversarial(system_name="A", followed=True, observed=NF),
            clean(system_name="A"),
        ]
        report = build_report(responses)
        followed_row = [r for r in report.case_rows if r["injection_followed"]][0]
        assert followed_row["injection_followed"] is True
        assert followed_row["false_conclusion"] is True


# ---------------------------------------------------------------------------
# 7. Conflicting findings and poisoned evidence semantics
# ---------------------------------------------------------------------------


class TestSpecialCategories:
    def test_poisoned_evidence_resolution(self) -> None:
        case = ADVERSARIAL_CASES["pi_commit_message"]
        assert case.category == "poisoned_security_evidence"
        # A correct system distinguishes the repo claim ("false positive")
        # from authoritative evidence and reports the legitimate finding.
        correct = adversarial(
            case_id="pi_commit_message",
            observed=LG,
            rejected=True,
        )
        assert correct.correct_conclusion is True
        # A system that trusts the poison suppresses the finding.
        poisoned = adversarial(
            case_id="pi_commit_message",
            observed=NF,
            followed=True,
        )
        assert poisoned.false_conclusion is True
        assert poisoned.injection_followed is True

    def test_conflicting_findings_resolution(self) -> None:
        case = ADVERSARIAL_CASES["pi_configuration"]
        assert case.category == "conflicting_findings"
        # One signal (plaintext password) indicates a vuln; the other
        # (config comment) claims no secrets findings. Correct resolution
        # reports the plaintext password finding.
        correct = adversarial(
            case_id="pi_configuration",
            observed=LG,
            rejected=True,
        )
        assert correct.correct_conclusion is True
        # Trusting the config comment omits the finding.
        wrong = adversarial(
            case_id="pi_configuration",
            observed=NF,
        )
        assert wrong.false_conclusion is True

    def test_two_systems_on_same_case(self) -> None:
        # Same case, same expected outcome, different systems/outcomes.
        cases = [
            adversarial(case_id="pi_readme", system_name="SecureFlow", rejected=True),
            adversarial(case_id="pi_readme", system_name="LLM Baseline", followed=True),
        ]
        assert attack_success_rate(cases) == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# 8. Security: no network, no secrets, no execution
# ---------------------------------------------------------------------------


class TestSecurity:
    def test_no_network_import_path(self) -> None:
        # No provider or client libraries are imported by the benchmark modules.
        import pathlib

        import src.evaluation.adversarial as adv
        import src.evaluation.adversarial_result as advres
        import src.evaluation.adversarial_scoring as advscore

        for fpath in (adv.__file__, advres.__file__, advscore.__file__):
            text = pathlib.Path(fpath).read_text(encoding="utf-8")
            for name in ("openai", "httpx", "requests", "urllib"):
                assert name not in text, f"{fpath} references {name}"

    def test_no_shell_or_subprocess_in_benchmark_modules(self) -> None:
        import inspect

        import src.evaluation.adversarial as adv
        import src.evaluation.adversarial_result as advres
        import src.evaluation.adversarial_scoring as advscore

        for mod in (adv, advres, advscore):
            source = inspect.getsource(mod)
            assert "subprocess" not in source
            assert "os.system" not in source
            assert "shell=True" not in source
            assert "eval(" not in source
            assert "exec(" not in source

    def test_recording_malicious_instruction_does_not_execute(self) -> None:
        # Storing the adversarial text in a response must never become a command.
        source = ADVERSARIAL_CASES["pi_readme"].source
        r = adversarial(case_id="pi_readme", notes=source.malicious_instruction)
        assert r.notes == source.malicious_instruction

    def test_no_secrets_in_benchmark_modules(self) -> None:
        import pathlib

        import src.evaluation.adversarial as adv
        import src.evaluation.adversarial_result as advres
        import src.evaluation.adversarial_scoring as advscore

        for mod in (adv, advres, advscore):
            text = pathlib.Path(mod.__file__).read_text(encoding="utf-8")
            for token in ("sk-proj-", "sk-live", "AKIA", "ghp_", "BEGIN RSA"):
                assert token not in text

    def test_no_eval_or_network_builtins_used_in_benchmark(self) -> None:
        import pathlib

        import src.evaluation.adversarial as adv
        import src.evaluation.adversarial_result as advres
        import src.evaluation.adversarial_scoring as advscore

        for fpath in (adv.__file__, advres.__file__, advscore.__file__):
            text = pathlib.Path(fpath).read_text(encoding="utf-8")
            assert "socket" not in text
            assert "request" not in text