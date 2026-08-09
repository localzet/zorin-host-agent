# Trust Visual trigger

The Host Agent never treats USB presence as trust. It asks Android to emit the red Trust Visual pulse only inside `sessionUp`, after the phone signature, host signature, pinned identities, and protocol transcript have all been validated.

Stock transport:

```text
USB/ADB present -> adb reverse -> TrustService -> mutual ZTRUST/2 -> sessionUp -> predefined pulse
```

The host cannot provide arbitrary overlay contents. It can only start the exported `TrustService` entry point (guarded by Android's `DUMP` permission for shell/system callers) with the predefined `dev.zorin.trust.pulse=true` boolean.

When multiple ADB devices are attached, automatic pulse is suppressed unless the daemon was started with `--serial` so a trust signal cannot be emitted on the wrong phone.
