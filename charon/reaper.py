"""Phase 6 — the Reaper.

Identities that outlive their usefulness are a standing liability: an idle agent
is an unused key, an orphaned agent is a backdoor whose owner is gone, and an
over-scoped agent is excess blast radius. The reaper continuously sweeps the
registry and acts:

  * IDLE      — an ACTIVE agent with no recent activity is moved to IDLE.
  * ORPHAN    — an agent whose owner has departed is revoked and decommissioned.
  * DECOMMISSION — an IDLE agent that stays idle past a grace period is retired.
  * DRIFT     — an agent granted scopes it never exercises is flagged (least
                privilege regression), without changing its state.

Every action flows through the audited lifecycle transitions, so the reaper's
decisions are themselves part of the tamper-evident record. ``run_once`` can run
in ``apply=False`` (dry-run) mode for the dashboard's "what would the reaper do"
preview.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from .lifecycle import LifecycleState
from .service import Registry


@dataclass
class ReaperAction:
    agent_id: str
    name: str
    action: str
    detail: str


class Reaper:
    def __init__(
        self,
        registry: Registry,
        idle_after: float = 86_400,  # 24h with no activity -> IDLE
        decommission_after_idle: float = 7 * 86_400,  # idle 7d -> decommission
        departed_owners: set[str] | None = None,
    ):
        self._reg = registry
        self._idle_after = idle_after
        self._decommission_after_idle = decommission_after_idle
        self._departed = departed_owners or set()

    def run_once(self, now: float | None = None, apply: bool = True) -> list[ReaperAction]:
        now = now if now is not None else time.time()
        actions: list[ReaperAction] = []
        for agent in self._reg.list():
            if agent.state == LifecycleState.DECOMMISSIONED:
                continue

            # 1) ORPHAN — owner gone: revoke then decommission.
            if agent.owner in self._departed and agent.state in (
                LifecycleState.PROVISIONED,
                LifecycleState.ACTIVE,
                LifecycleState.IDLE,
            ):
                actions.append(
                    ReaperAction(agent.id, agent.name, "decommissioned-orphan",
                                 f"owner {agent.owner!r} departed")
                )
                if apply:
                    self._reg.transition(
                        agent.id, LifecycleState.REVOKED, reason="reaped-orphan"
                    )
                    self._reg.transition(
                        agent.id, LifecycleState.DECOMMISSIONED, reason="reaped-orphan"
                    )
                continue

            last = agent.last_seen if agent.last_seen is not None else agent.created_at

            # 2) IDLE — active but quiet.
            if agent.state == LifecycleState.ACTIVE and (now - last) > self._idle_after:
                actions.append(
                    ReaperAction(agent.id, agent.name, "idled",
                                 f"no activity for {int(now - last)}s")
                )
                if apply:
                    self._reg.transition(
                        agent.id, LifecycleState.IDLE, reason="reaped-idle"
                    )

            # 3) DECOMMISSION — idle past the grace period.
            elif agent.state == LifecycleState.IDLE and (
                now - last
            ) > self._decommission_after_idle:
                actions.append(
                    ReaperAction(agent.id, agent.name, "decommissioned-idle",
                                 f"idle for {int(now - last)}s")
                )
                if apply:
                    self._reg.transition(
                        agent.id, LifecycleState.DECOMMISSIONED, reason="reaped-idle"
                    )

            # 4) DRIFT — granted scopes the agent never exercises.
            if agent.state in (LifecycleState.ACTIVE, LifecycleState.IDLE):
                used = self._reg.used_scopes(agent.spiffe_id or "")
                granted = set(agent.scopes)
                unused = granted - used
                if used and unused:  # has used at least one scope but not all
                    actions.append(
                        ReaperAction(agent.id, agent.name, "drift-flagged",
                                     f"unused scopes: {sorted(unused)}")
                    )
                    if apply:
                        self._reg.record_drift(agent.id, list(granted), list(used))
        return actions
