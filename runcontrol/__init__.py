"""Host-side control of an analysis guest.

**Everything in this package runs on the host, and nothing in it trusts the
guest.** `dynamic_analysis` is the other half: it runs *inside* the guest and
produces a case folder. This package reverts a snapshot, delivers a sample,
arms containment, boots, waits, powers off, and collects what the guest wrote.

It is deliberately not called a sandbox. See *The run controller* in
docs/HANDOFF.md for why, and for the design this implements.
"""
