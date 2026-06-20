import unittest

from charon.lifecycle import (
    IllegalTransition,
    LifecycleState,
    TransitionContext,
    TransitionGuardFailed,
    can_transition,
    check_transition,
    is_terminal,
)


class LifecycleTests(unittest.TestCase):
    def test_legal_transition(self):
        check_transition(
            LifecycleState.PROVISIONED,
            LifecycleState.ACTIVE,
            TransitionContext(attested=True),
        )  # should not raise

    def test_illegal_transition_rejected(self):
        with self.assertRaises(IllegalTransition):
            check_transition(LifecycleState.PROVISIONED, LifecycleState.IDLE)

    def test_activation_requires_attestation(self):
        with self.assertRaises(TransitionGuardFailed):
            check_transition(
                LifecycleState.PROVISIONED,
                LifecycleState.ACTIVE,
                TransitionContext(attested=False),
            )

    def test_decommissioned_is_terminal(self):
        self.assertTrue(is_terminal(LifecycleState.DECOMMISSIONED))
        for state in LifecycleState:
            self.assertFalse(
                can_transition(LifecycleState.DECOMMISSIONED, state)
            )

    def test_revoked_can_only_decommission(self):
        self.assertTrue(
            can_transition(LifecycleState.REVOKED, LifecycleState.DECOMMISSIONED)
        )
        self.assertFalse(
            can_transition(LifecycleState.REVOKED, LifecycleState.ACTIVE)
        )


if __name__ == "__main__":
    unittest.main()
