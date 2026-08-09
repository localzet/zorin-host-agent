# Runtime bootstrap recovery

Normal paired-host reconnects start only `dev.zorin.trustruntime.TrustService`; they do not start the UI Activity. Pairing is the sole normal path that intentionally opens the phone UI.

If Android accepts `am start-foreground-service` but the service process crashes before a trust heartbeat arrives, the host limits retries to one every 30 seconds until the USB/ADB connection is cycled. This avoids user-visible or CPU-intensive crash loops.
