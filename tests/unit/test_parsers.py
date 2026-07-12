from pathlib import Path
from ramscope.parsers.cmdline_parser import CmdlineParser
from ramscope.parsers.malfind_parser import MalfindParser
from ramscope.parsers.network_parser import NetworkParser
from ramscope.parsers.process_parser import ProcessParser

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_process_parser() -> None:
    rows = ProcessParser().parse_file(FIXTURES / "volatility_pslist_sample.json")
    assert rows[1]["pid"] == 4120
    assert rows[1]["name"] == "powershell.exe"


def test_cmdline_parser() -> None:
    rows = CmdlineParser().parse_file(FIXTURES / "volatility_cmdline_sample.json")
    assert rows[0]["command_line"].startswith("powershell.exe")


def test_network_parser() -> None:
    rows = NetworkParser().parse_file(FIXTURES / "volatility_netscan_sample.json")
    assert rows[0].remote_addr == "45.90.10.20"


def test_malfind_parser() -> None:
    rows = MalfindParser().parse_file(FIXTURES / "volatility_malfind_sample.json")
    assert rows[0].has_pe_header is True
