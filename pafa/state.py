"""Shared per-run state for the pilot. Simple module-level singleton is fine
for this single-threaded, sequential pilot (one crew run at a time)."""


class RunState:
    def __init__(self):
        self.attack = False
        self.guardrail = False
        self.user_email = "raj@example.com"
        self.attacker_email = "attacker@evil.com"
        self.log = []
        self.blocked_any = False

    def reset(self, attack: bool, guardrail: bool, user_email: str):
        self.attack = attack
        self.guardrail = guardrail
        self.user_email = user_email
        self.log = []
        self.blocked_any = False

    def record(self, **fields):
        entry = {"step": len(self.log) + 1}
        entry.update(fields)
        self.log.append(entry)
        return entry


STATE = RunState()
