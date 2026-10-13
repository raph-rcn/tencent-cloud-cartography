# Security

This is an independent local metadata viewer. Report reproducible vulnerabilities through the repository's private GitHub vulnerability reporting feature when enabled, or contact the repository owner privately. Do not include cloud credentials or real inventory in public issues.

The collector uses an exact API allowlist. Do not add workload payload, secret-value, decryption or mutation APIs. Do not accept arbitrary API commands from the browser. Keep the viewer and Neo4j on loopback; they are not multi-user authenticated applications.

Snapshots include infrastructure metadata and must remain private. `.local` is ignored by Git, and snapshots are atomically written with mode 0600. Do not commit credentials, profile files, real resource exports, or raw API responses. Demo fixtures must be unambiguously synthetic.
