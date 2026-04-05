# ═══════════════════════════════════════════════
#  history.py  —  Transfer History (session log)
# ═══════════════════════════════════════════════

import datetime
from dataclasses import dataclass


@dataclass
class TransferRecord:
    time: str
    direction: str
    filename: str
    size: int
    peer: str
    status: str
    elapsed: float


class TransferHistory:
    """
    Keeps an in-memory log of all sent/received file transfers
    for the current session (max 100 records).
    """

    def __init__(self) -> None:
        self.records: list[TransferRecord] = []

    def add(self, direction: str, filename: str, size_bytes: int,
            peer: str, status: str, elapsed: float = 0.0) -> None:
        """
        Add a transfer record.

        Args:
            direction  : "SENT" or "RECEIVED"
            filename   : original filename
            size_bytes : total bytes transferred
            peer       : IP:port string
            status     : "OK" or "FAILED"
            elapsed    : transfer duration in seconds
        """
        record = TransferRecord(
            time=datetime.datetime.now().strftime("%H:%M:%S"),
            direction=direction,
            filename=filename,
            size=size_bytes,
            peer=peer,
            status=status,
            elapsed=round(elapsed, 2)
        )
        self.records.insert(0, record)
        # Keep max 100 records
        self.records = self.records[:100]

    def clear(self) -> None:
        self.records.clear()

    def speed_str(self, record: TransferRecord) -> str:
        """Returns formatted KB/s string for a record."""
        if record.elapsed > 0:
            return f"{record.size / 1024 / record.elapsed:.0f}"
        return "—"