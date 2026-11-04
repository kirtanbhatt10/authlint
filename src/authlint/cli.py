"""Command-line interface: authlint provider | jwks | client | rules."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .client import check_client
from .fetch import LoadError, load_document, load_provider
from .findings import SEVERITIES, Finding, severity_rank, sort_findings
from .jwks import check_jwks
from .provider import check_provider
from .report import FORMATS, render
from .rules import RULES

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2
EXIT_INTERRUPTED = 130


def _timeout(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid number: {value!r}") from None
    if not 0 < seconds <= 300:
        raise argparse.ArgumentTypeError("must be greater than 0 and at most 300 seconds")
    return seconds


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="authlint",
        description="Audit OAuth 2.0 and OpenID Connect providers, key sets and clients against the OAuth security BCP (RFC 9700).",
    )
    parser.add_argument("--version", action="version", version=f"authlint {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("-F", "--format", choices=FORMATS, default="text", help="output format (default: text)")
        p.add_argument("-o", "--output", help="write the report to a file instead of stdout")
        p.add_argument(
            "--fail-on", choices=SEVERITIES, default="high", help="exit 1 when a finding is at least this severe (default: high)"
        )
        p.add_argument("--ignore", default="", help="comma-separated rule ids to skip, e.g. AL110,AL111")
        p.add_argument("--timeout", type=_timeout, default=10.0, help="network timeout in seconds (default: 10)")
        p.add_argument("--no-color", action="store_true", help="disable colors in text output")

    provider = sub.add_parser("provider", help="audit provider metadata from an issuer URL or a JSON file")
    provider.add_argument("target", help="issuer URL, .well-known metadata URL, or a metadata JSON file")
    provider.add_argument("--jwks", help="JWKS URL or file to audit instead of the provider's jwks_uri")
    provider.add_argument("--no-jwks", action="store_true", help="do not fetch the provider's jwks_uri")
    common(provider)

    jwks = sub.add_parser("jwks", help="audit a JSON Web Key Set from a URL or file")
    jwks.add_argument("target")
    common(jwks)

    client = sub.add_parser("client", help="audit client registrations (RFC 7591 JSON, one object or a list)")
    client.add_argument("target")
    common(client)

    sub.add_parser("rules", help="list every rule")
    return parser


def _filter(findings: list[Finding], ignore: set[str]) -> list[Finding]:
    return sort_findings([f for f in findings if f.rule not in ignore])


def run_provider(args: argparse.Namespace) -> list[dict]:
    meta, expected_issuer, source = load_provider(args.target, args.timeout)
    results = [{"target": "provider", "source": source, "findings": check_provider(meta, expected_issuer)}]
    jwks_target = args.jwks
    if not jwks_target and not args.no_jwks and expected_issuer and isinstance(meta, dict):
        uri = meta.get("jwks_uri")
        if isinstance(uri, str) and uri.startswith("https://"):
            jwks_target = uri
    if jwks_target:
        results.append(
            {"target": "jwks", "source": jwks_target, "findings": check_jwks(load_document(jwks_target, args.timeout))}
        )
    return results


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except KeyboardInterrupt:
        print("authlint: interrupted", file=sys.stderr)
        return EXIT_INTERRUPTED


def _print(text: str) -> None:
    """Print to stdout, tolerating a reader that exits early (e.g. `authlint rules | head`)."""
    try:
        print(text)
        sys.stdout.flush()
    except BrokenPipeError:
        # Point stdout at devnull so the interpreter does not raise again when it flushes on exit.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())


def _main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "rules":
        _print("\n".join(f"{r.id}  {r.severity:<8} {r.target:<8} {r.title}  [{r.reference}]" for r in RULES.values()))
        return EXIT_OK

    ignore = {r.strip().upper() for r in args.ignore.split(",") if r.strip()}
    unknown = sorted(ignore - RULES.keys())
    if unknown:
        print(f"authlint: unknown rule id(s): {', '.join(unknown)}", file=sys.stderr)
        return EXIT_ERROR

    try:
        if args.command == "provider":
            results = run_provider(args)
        elif args.command == "jwks":
            results = [
                {"target": "jwks", "source": args.target, "findings": check_jwks(load_document(args.target, args.timeout))}
            ]
        else:
            results = [
                {"target": "client", "source": args.target, "findings": check_client(load_document(args.target, args.timeout))}
            ]
    except LoadError as exc:
        print(f"authlint: {exc}", file=sys.stderr)
        return EXIT_ERROR

    for result in results:
        result["findings"] = _filter(result["findings"], ignore)

    color = (
        args.format == "text" and not args.no_color and not args.output and sys.stdout.isatty() and "NO_COLOR" not in os.environ
    )
    output = render(results, args.format, color)
    threshold = severity_rank(args.fail_on)
    failed = any(severity_rank(f.severity) >= threshold for r in results for f in r["findings"])
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(output + "\n")
        except OSError as exc:
            print(f"authlint: cannot write {args.output}: {exc.strerror}", file=sys.stderr)
            return EXIT_ERROR
    else:
        _print(output)
    return EXIT_FINDINGS if failed else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
