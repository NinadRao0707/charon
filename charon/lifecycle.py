"""The identity lifecycle state machine.

Every non-human identity moves through a constrained set of states. Illegal
transitions are rejected, and certain transitions are *guarded* by conditions
(for example: an identity cannot become ACTIVE until it has been attested).

    PROVISIONED ---- attest ----> ACTIVE <----+
         |                          | |       |
         |                          | +--idle-+--> IDLE
         |                          |                |
         +-------- revoke ----------+----------------+--> REVOKED
                                                            |
                                              decommission  v
   IDLE/REVOKED -------------------------------------> DECOMMISSIONED (terminal)

Keeping this logic in one place, separate from storage and HTTP, is what lets
the same rules be unit-tested in isolation and reused by the reaper.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Callable


class LifecycleState(str, enum.Enum):
    PROVISIONED = "PROVISIONED"
    ACTIVE = "ACTIVE"
    IDLE = "IDLE"
    REVOKED = "REVOKED"
    DECOMMISSIONED = "DECOMMISSIONED"


class IllegalTransition(Exception):
    """Raised when a state transition is not permitted."""


class TransitionGuardFailed(Exception):
    """Raised when a transition is structurally legal but a guard rejected it."""


# The directed graph of permitted transitions.
_ALLOWED: dict[LifecycleState, set[LifecycleState]] = {
    LifecycleState.PROVISIONED: {LifecycleState.ACTIVE, LifecycleState.REVOKED},
    LifecycleState.ACTIVE: {LifecycleState.IDLE, LifecycleState.REVOKED},
    LifecycleState.IDLE: {
        LifecycleState.ACTIVE,
        LifecycleState.REVOKED,
        LifecycleState.DECOMMISSIONED,
    },
    LifecycleState.REVOKED: {LifecycleState.DECOMMISSIONED},
    LifecycleState.DECOMMISSIONED: set(),  # terminal
}


@dataclass(frozen=True)
class TransitionContext:
    """Information a guard may inspect when deciding whether to allow a move."""

    attested: bool = False
    reason: str | None = None


# A guard returns None if it permits the transition, or a string explaining the
# rejection. Guards are keyed by (from_state, to_state).
Guard = Callable[[TransitionContext], str | None]


def _require_attested(ctx: TransitionContext) -> str | None:
    if not ctx.attested:
        return "cannot activate an identity that has not been attested"
    return None


_GUARDS: dict[tuple[LifecycleState, LifecycleState], Guard] = {
    (LifecycleState.PROVISIONED, LifecycleState.ACTIVE): _require_attested,
    (LifecycleState.IDLE, LifecycleState.ACTIVE): _require_attested,
}


def can_transition(current: LifecycleState, target: LifecycleState) -> bool:
    """True if the transition is structurally permitted (ignores guards)."""
    return target in _ALLOWED[current]


def check_transition(
    current: LifecycleState,
    target: LifecycleState,
    ctx: TransitionContext | None = None,
) -> None:
    """Validate a transition, raising on any violation.

    Raises IllegalTransition for a structurally forbidden move, or
    TransitionGuardFailed if a guard rejects an otherwise-legal move.
    """
    if not can_transition(current, target):
        raise IllegalTransition(f"{current.value} -> {target.value} is not allowed")
    guard = _GUARDS.get((current, target))
    if guard is not None:
        rejection = guard(ctx or TransitionContext())
        if rejection is not None:
            raise TransitionGuardFailed(rejection)


def is_terminal(state: LifecycleState) -> bool:
    return len(_ALLOWED[state]) == 0
