"""Human-readable terminal reports."""
from collections import Counter
from core.verifier import VerificationResult

class Reporter:
    @staticmethod
    def verification(result: VerificationResult) -> None:
        print("=" * 40, "LOGGUARD INTEGRITY CHECK", "=" * 40, sep="\n")
        print(f"File: {result.file_path}\nStatus: {result.status.value}\n")
        print(f"Expected SHA256:\n{result.expected_hash}\n")
        print(f"Current SHA256:\n{result.current_hash or 'Unavailable'}\n")
        print(f"Severity: {result.severity}")

    @staticmethod
    def scan(results: list[VerificationResult]) -> None:
        print(f"{'FILE':<60} STATUS")
        for result in results:
            print(f"{result.file_path:<60} {result.status.value}")
        counts = Counter(result.status.value for result in results)
        print(f"\nSummary:\nTotal: {len(results)}")
        for status, count in sorted(counts.items()):
            print(f"{status.title().replace('_', ' ')}: {count}")

    @staticmethod
    def status(records) -> None:
        print(f"{'FILE':<60} STATUS       LAST CHECKED")
        for item in records:
            print(f"{item.file_path:<60} {item.status:<12} {item.last_checked or 'Never'}")

    @staticmethod
    def alerts(records) -> None:
        print(f"{'TIMESTAMP':<20} {'SEVERITY':<9} {'EVENT':<20} FILE / MESSAGE")
        for item in records:
            print(f"{item.detected_at:<20} {item.severity:<9} {item.event_type:<20} "
                  f"{item.file_path} — {item.message}")

    @staticmethod
    def history(records) -> None:
        print(f"{'TIMESTAMP':<20} {'ACTION':<22} {'RESULT':<20} TARGET")
        for item in records:
            print(f"{item.timestamp:<20} {item.action:<22} {item.result:<20} {item.target}")
