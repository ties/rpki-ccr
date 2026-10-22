#!/usr/bin/env python3
"""Print the changes from one CCR file to another.

Usage: python ccr_diff.py [--summary] OLD NEW
"""

import argparse

from rpki_ccr import Ccr, ManifestInstance


def describe(mi: ManifestInstance) -> str:
    uris = ",".join(location.uri for location in mi.locations)
    seqnum = f"{mi.manifest_number:X}"
    seqnum = seqnum.rjust(len(seqnum) + len(seqnum) % 2, "0")  # whole octets, like rpki-client
    return f"seqnum {seqnum} thisupdate {mi.this_update:%Y-%m-%dT%H:%M:%SZ} {uris}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", action="store_true", help="counts only")
    parser.add_argument("--lenient", action="store_true", help="skip validation")
    parser.add_argument("old")
    parser.add_argument("new")
    args = parser.parse_args()
    checks = dict(verify_hashes=not args.lenient, check_ordering=not args.lenient, check_consistency=not args.lenient)
    before = Ccr.from_file(args.old, **checks)
    after = Ccr.from_file(args.new, **checks)
    diff = before.diff(after)
    print(f"Before: {args.old} produced at {diff.before_produced_at}")
    print(f"After:  {args.new} produced at {diff.after_produced_at}")

    if (m := diff.manifests) is not None:
        print(f"Manifests: +{len(m.added)} -{len(m.removed)} ({m.unchanged} unchanged); "
              f"issuers: {len(m.issuers)} changed ({m.unchanged_issuers} unchanged)")
        if not args.summary:
            for change in m.issuers:
                sign = {"added": "+", "removed": "-", "updated": "~"}[change.kind]
                print(f"  {sign} aki {change.aki.hex().upper()}")
                for mi in change.before:
                    print(f"      was {describe(mi)}")
                for mi in change.after:
                    print(f"      now {describe(mi)}")
    if (v := diff.roa_payloads) is not None:
        print(f"VRPs: +{len(v.added)} -{len(v.removed)} ({v.unchanged} unchanged)")
        if not args.summary:
            for vrp in v.removed:
                print(f"  - {vrp}")
            for vrp in v.added:
                print(f"  + {vrp}")
    if (a := diff.aspa_payloads) is not None:
        print(f"ASPAs: +{len(a.added)} -{len(a.removed)} ~{len(a.updated)} ({a.unchanged} unchanged)")
        if not args.summary:
            for s in a.removed:
                print(f"  - customer {s.customer_asn}")
            for s in a.added:
                print(f"  + customer {s.customer_asn}")
            for u in a.updated:
                parts = [f"+{p}" for p in u.providers_added] + [f"-{p}" for p in u.providers_removed]
                print(f"  ~ customer {u.customer_asn}: {' '.join(parts)}")
    if (t := diff.trust_anchors) is not None:
        print(f"Trust anchors: +{len(t.added)} -{len(t.removed)} ({t.unchanged} unchanged)")
        if not args.summary:
            for ski in t.removed:
                print(f"  - {ski.hex().upper()}")
            for ski in t.added:
                print(f"  + {ski.hex().upper()}")
    if (r := diff.router_keys) is not None:
        print(f"Router keys: +{len(r.added)} -{len(r.removed)} ({r.unchanged} unchanged)")
        if not args.summary:
            for key in r.removed:
                print(f"  - AS {key.asn} ski {key.ski.hex().upper()}")
            for key in r.added:
                print(f"  + AS {key.asn} ski {key.ski.hex().upper()}")
    if not diff:
        print("No changes.")


if __name__ == "__main__":
    main()
