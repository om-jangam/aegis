"""What the screen does when something goes wrong behind it.

A security tool that quietly shows an empty list where it should show an error
is worse than one that crashes: the person reads "nothing here" and believes
it. These tests cover the two places that went wrong in practice - handing over
to an elevated copy, and failing to read the fix history - and pin the
behaviour that makes a failure visible.

Flet is not started here. Both methods under test need only a service and a
page, so they are driven on a bare instance with stand-ins for both.
"""
import flet as ft
import pytest

from aegis.ui.app import AegisApp
from aegis.ui.views.security_check_view import SecurityCheckView


class FakeService:
    """Records whether it was paused or shut down."""

    def __init__(self, hardening=None):
        self.stopped = False
        self.closed = False
        self.hardening = hardening

    def stop(self) -> None:
        self.stopped = True

    def close(self) -> None:
        self.closed = True


class FakeWindow:
    def __init__(self):
        self.close_requested = False

    def close(self) -> None:
        self.close_requested = True


class FakePage:
    def __init__(self, web: bool = False):
        self.web = web
        self.window = FakeWindow()
        self.tasks: list = []

    def run_task(self, fn, *args):
        self.tasks.append(fn)


def make_app(*, web: bool) -> AegisApp:
    """An app object with only what the handover touches."""
    app = object.__new__(AegisApp)
    app.service = FakeService()
    app.page = FakePage(web=web)
    app.toasts: list[tuple[str, bool]] = []
    app.toast = lambda message, ok=True: app.toasts.append((message, ok))
    app.synced = False
    app.sync_monitor_button = lambda: setattr(app, "synced", True)
    return app


# --------------------------------------------------------------------------- #
# Handing over to an elevated copy
# --------------------------------------------------------------------------- #
def test_handing_over_stops_watching_but_keeps_the_database_open():
    """Windows only says a process was created, not that Aegis is running.

    Closing the store on that promise left a fully drawn window whose every
    database read failed, so the fix history silently emptied itself.
    """
    app = make_app(web=False)
    app.close_for_restart()

    assert app.service.stopped, "monitoring must stop so the new copy can watch"
    assert not app.service.closed, "the database must stay usable if the new copy dies"
    assert app.synced, "the header must stop claiming it is still watching"


@pytest.mark.parametrize("web", [True, False])
def test_the_window_is_never_destroyed_on_an_unverified_promise(web):
    """Closing it would leave nothing at all if the new copy never starts.

    In a browser there is no window to close anyway: ``window.close`` raises
    nothing and times out ten seconds later inside a callback, so the person
    would be told precisely nothing.
    """
    app = make_app(web=web)
    app.close_for_restart()

    assert app.page.tasks == [], "nothing may be torn down before the new copy runs"
    assert not app.page.window.close_requested
    assert app.toasts, "the person must be told which window to use"
    assert "administrator" in app.toasts[0][0].lower()


def test_the_person_is_told_even_when_stopping_fails():
    app = make_app(web=True)

    def explode() -> None:
        raise RuntimeError("collector thread wedged")

    app.service.stop = explode
    app.close_for_restart()          # must not raise
    assert app.toasts


# --------------------------------------------------------------------------- #
# Reading the fix history
# --------------------------------------------------------------------------- #
class Hardening:
    def __init__(self, records=None, error=None):
        self.records = records or []
        self.error = error

    def history(self, limit):
        if self.error is not None:
            raise self.error
        return self.records


def make_view(hardening) -> SecurityCheckView:
    view = object.__new__(SecurityCheckView)
    view.service = FakeService(hardening=hardening)
    view.history = ft.ListView()
    view.safe_update = lambda: None
    return view


def rendered(view) -> str:
    """Every piece of text the history panel is showing."""
    parts = []
    for control in view.history.controls:
        parts.append(getattr(control, "value", "") or "")
        for child in getattr(control, "controls", []) or []:
            parts.append(getattr(child, "value", "") or "")
    return " ".join(parts)


def test_an_empty_history_says_nothing_has_been_fixed():
    view = make_view(Hardening(records=[]))
    view._show_history()
    assert "No fixes applied yet" in rendered(view)


def test_a_failure_to_read_the_history_is_not_shown_as_an_empty_history():
    """The bug: a closed database rendered as "No fixes applied yet."

    Undo lives in this panel, so an error disguised as emptiness also makes
    every undo button disappear without a word.
    """
    view = make_view(Hardening(error=RuntimeError("Cannot operate on a closed database")))
    view._show_history()

    text = rendered(view)
    assert "No fixes applied yet" not in text
    assert "could not" in text.lower()


@pytest.mark.parametrize("failure", [
    RuntimeError("boom"),
    OSError("disk gone"),
])
def test_any_failure_to_read_is_reported_rather_than_hidden(failure):
    view = make_view(Hardening(error=failure))
    view._show_history()
    assert "could not" in rendered(view).lower()
