# Contributing

Keep the host agent a small authentication/presence component rather than a generic remote administration daemon. Network commands are fixed by the ZTRUST protocol; commands received from the phone must never be passed to a local shell.

Local owner-configured hooks are acceptable because they are configured on the host itself, not supplied over USB.
