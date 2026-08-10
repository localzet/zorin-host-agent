# Zorin Host Agent

## v0.4.0

Mutual-authentication host runtime for Zorin Trust Center. In addition to the ZTRUST/2 session and ZOWNER/1 proof broker, v0.4 emits a bounded local event timeline and a host-info snapshot consumed by the WPF Trust Center.

`status` now separates Device Trust, Owner Presence, Owner Actions and Transport instead of collapsing them into one "Owner mode" label.
