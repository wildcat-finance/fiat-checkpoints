"""Validate one sealed input inside a pinned gVisor sandbox.

The supervisor (`sandbox`) owns the sandbox, its limits and its output; the
in-sandbox `runner` calls the released `verify_native`; `outputs` turns the
bounded result into a typed outcome; `service` joins it to current trust and
records the publication intent. See adr/isolate-validator-trust.
"""
