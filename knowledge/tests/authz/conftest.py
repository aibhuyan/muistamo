"""The authz suite may fail or pass. It may never skip or xfail."""

import pytest


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]):
    report = yield
    # An xfailed test reports as skipped and carries `wasxfail`; pytest leaves any report with
    # that attribute out of the exit status, so it must go too.
    if report.skipped or hasattr(report, "wasxfail"):
        report.outcome = "failed"
        if hasattr(report, "wasxfail"):
            del report.wasxfail
        report.longrepr = (
            f"{item.nodeid}: authz tests must never be skipped or xfailed "
            f"(CLAUDE.md invariant 1). Original reason: {report.longrepr}"
        )
    return report
