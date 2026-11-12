from fido2.server import Fido2Server

from acme_tokens import Ledger


class KeyChecker:
    def __init__(self, rp):
        self.server = Fido2Server(rp)

    def start(self, creds):
        return self.server.authenticate_begin(creds)

    def assertion_ok(self, state, creds, response):
        try:
            self.server.authenticate_complete(state, creds, response)
        except ValueError:
            return False
        return True


def ledger_accepts(ledger: Ledger, token):
    try:
        ledger.verify_entry(token)
    except Exception:
        return False
    return True
