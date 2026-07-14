# Synthetic demonstration case

This directory contains a deliberately small, entirely synthetic Defender-style
timeline. It uses reserved domains and documentation IP networks and contains no
real case or threat intelligence.

## Run it

1. Start Investigator and create a case named `Synthetic demo`.
2. On **Evidence**, upload `synthetic-defender.jsonl`.
3. Wait for ingestion and deterministic detection to finish.
4. Inspect **Events**, **Timeline**, **Entity Map**, and **Findings**.

The import should produce exactly nine events spanning filesystem, process,
persistence, network, and account categories. It demonstrates a downloaded file,
a PowerShell child process, a Run-key write, a documentation-network connection,
a synthetic remote-thread action, and failed logons followed by success.

The precise finding count is not a stable API because rules improve between
versions. The release smoke test asserts record count and normalization
categories; versioned release notes call out intentional detection changes.

This fixture is safe to share, but it is intentionally unrealistic and must not
be used to measure detection coverage or performance.
