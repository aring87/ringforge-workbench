"""Outbound integrations: getting RingForge results into other systems.

Nothing in here is allowed to affect an analysis. A SIEM being down, a token
being wrong, or a network being deliberately disarmed must never turn a
successful triage into a failed one, so every function in this package reports
failure by returning a status dict rather than raising.
"""
