import sys
import typing

from PyKCS11 import PyKCS11Lib, Session
from PyKCS11.LowLevel import CKF_RW_SESSION


def run(lib: PyKCS11Lib, so: str, slot: int, pin: str, code: typing.Callable[[Session], None]):
    lib.load(so)
    session = lib.openSession(slot, CKF_RW_SESSION)
    session.login(pin)

    try:
        code(session)
    except Exception as e:  # whatever exception occurs, logout and close the session
        print(e, file=sys.stderr)
        print("logout and close session")

    session.logout()
    session.closeSession()
    lib.unload()
