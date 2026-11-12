from django.contrib.auth.tokens import PasswordResetTokenGenerator


class InvitationTokenGenerator(PasswordResetTokenGenerator):
    key_salt = "edge.invitation"


invitation_tokens = InvitationTokenGenerator()
