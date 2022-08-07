from django.db import models


class FirebaseMFASecret(models.Model):
    """Model for MFA Secret, that's required to generate login OTP.
    """
    firebase_user_id = models.CharField(max_length=255, primary_key=True)
    encrypted_mfa_secret = models.BinaryField()

    def __str__(self):
        return f"Encrypted MFA Secret of Firebase User: {self.firebase_user_id}"
