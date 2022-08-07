"""Utilities for Firebase Auth
"""

import pyotp
import requests
from requests.auth import HTTPBasicAuth
from django.conf import settings
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from dj_rest_firebase.models import FirebaseMFASecret
from dj_rest_firebase.endpoints import access_token_endpoints as ate


def is_mfa_enabled():
    """Read Django Settings to check if MFA is enabled
    :return: Flag to indicate whether MFA is enabled
    :rtype: bool
    """
    try:
        required_attr = settings.DRF_MFA_ENABLED
        is_enabled = True if required_attr else False
    except AttributeError:
        # Attribute not explicitly declared
        is_enabled = False
    except Exception as e:
        print(str(e))
        # Error, defaulting to False
        is_enabled = False
    return is_enabled


def get_default_callback_url():
    """Read Django Settings to get the Redirect URL for OAuth
    :return: Callback URL if available, else Empty String
    :rtype: str
    """
    try:
        callback_url = settings.DRF_OAUTH_CALLBACK_URL
    except AttributeError:
        # Attribute not explicitly declared
        callback_url = ""
    except Exception as e:
        print(str(e))
        # Error, defaulting to empty string
        callback_url = ""
    return callback_url


def add_mfa_for_new_user(firebase_user_id, mfa_secret, encryption_key, encryption_iv):
    """Add a new entry to the MFA Secret Django model
    :param str firebase_user_id: User ID from Firebase
    :param str mfa_secret: MFA Secret to generate OTPs
    :param str encryption_key: Encryption Key from the User
    :param str encryption_iv: Encryption IV from the User
    :return: SUCCESS or ERROR message
    :rtype: str
    """
    try:
        encryption_key_16 = encryption_key.encode("utf-8")[:16]
        encryption_iv_16 = encryption_iv.encode("utf-8")[:16]
        cipher = AES.new(encryption_key_16, AES.MODE_CBC, encryption_iv_16)
        encrypted_secret = cipher.encrypt(pad(mfa_secret.encode('utf-8'), AES.block_size))

        new_obj = FirebaseMFASecret(firebase_user_id=firebase_user_id, encrypted_mfa_secret=encrypted_secret)
        new_obj.save()
    except Exception as e:
        print(str(e))
        return "ERROR"
    return "SUCCESS"


def update_mfa_of_user(firebase_user_id, new_mfa_secret, encryption_key, encryption_iv):
    """Update the MFA Secret of a user
    :param str firebase_user_id: User ID from Firebase
    :param str new_mfa_secret: MFA Secret to generate OTPs
    :param str encryption_key: Encryption Key from the User
    :param str encryption_iv: Encryption IV from the User
    :return: SUCCESS or ERROR message
    :rtype: str
    """
    try:
        encryption_key_16 = encryption_key.encode("utf-8")[:16]
        encryption_iv_16 = encryption_iv.encode("utf-8")[:16]
        cipher = AES.new(encryption_key_16, AES.MODE_CBC, encryption_iv_16)
        encrypted_secret = cipher.encrypt(pad(new_mfa_secret.encode('utf-8'), AES.block_size))

        firebase_user = FirebaseMFASecret.objects.get(firebase_user_id=firebase_user_id)
        firebase_user.encrypted_mfa_secret = encrypted_secret
        firebase_user.save()
    except Exception as e:
        print(str(e))
        return "ERROR"
    return "SUCCESS"


def add_or_update_mfa_of_user(firebase_user_id, mfa_secret, encryption_key, encryption_iv):
    """Add a new entry to the MFA Secret Django model
    :param str firebase_user_id: User ID from Firebase
    :param str mfa_secret: MFA Secret to generate OTPs
    :param str encryption_key: Encryption Key from the User
    :param str encryption_iv: Encryption IV from the User
    :return: SUCCESS or ERROR message
    :rtype: str
    """
    if not FirebaseMFASecret.objects.filter(firebase_user_id=firebase_user_id):
        return add_mfa_for_new_user(firebase_user_id, mfa_secret, encryption_key, encryption_iv)
    else:
        return update_mfa_of_user(firebase_user_id, mfa_secret, encryption_key, encryption_iv)


def delete_mfa_of_user(firebase_user_id):
    """Delete MFA Secret entry from Django model
    :param str firebase_user_id: User ID from Firebase
    :return: SUCCESS or ERROR message
    :rtype: str
    """
    try:
        FirebaseMFASecret.objects.get(firebase_user_id=firebase_user_id).delete()
    except Exception as e:
        print(str(e))
        return "ERROR"
    return "SUCCESS"


def verify_otp(firebase_user_id, otp, encryption_key, encryption_iv):
    """Verify OTP against the MFA Secret stored
    :param str firebase_user_id: User ID from Firebase
    :param str otp: One Time Passcode
    :param str encryption_key: Encryption Key from the User
    :param str encryption_iv: Encryption IV from the User
    :return: Flag to indicate if the OTP is valid
    :rtype: bool
    """
    try:
        encryption_key_16 = encryption_key.encode("utf-8")[:16]
        encryption_iv_16 = encryption_iv.encode("utf-8")[:16]

        encrypted_mfa_secret = FirebaseMFASecret.objects.get(firebase_user_id=firebase_user_id).encrypted_mfa_secret
        decrypt_key = AES.new(encryption_key_16, AES.MODE_CBC, encryption_iv_16)
        plain_mfa_secret = unpad(decrypt_key.decrypt(encrypted_mfa_secret), AES.block_size).decode()
        token_valid = pyotp.TOTP(plain_mfa_secret).verify(otp, valid_window=2)
    except Exception as e:
        print(str(e))
        return False
    
    if not token_valid:
        return False
    else:
        return True


def is_valid_auth_provider(auth_provider):
    """Check if auth provider is valid
    :param str auth_provider: Auth Provider Name
    :return: Flag to indicate auth provider validity
    :rtype: bool
    """
    if auth_provider == "password" or auth_provider in ate.keys():
        return True
    else:
        return False


def is_valid_oauth_provider(auth_provider):
    """Check if OAuth provider is valid
    :param str auth_provider: OAuth Provider Name
    :return: Flag to indicate OAuth provider validity
    :rtype: bool
    """
    if auth_provider in ate.keys():
        return True
    else:
        return False


def get_oauth_token(auth_provider, code, client_id, client_secret, callback_url, challenge_txt):
    """Fetch Access Token from OAuth Provider
    :param str auth_provider: OAuth Provider Name
    :param str code: OAuth Provider Code
    :param str client_id: OAuth Provider Client ID
    :param str client_secret: OAuth Provider Client Secret
    :param str callback_url: OAuth Callback URL
    :param str challenge_txt: Challenge Text for some OAuth Providers such as Twitter
    :return: an accessToken
    :rtype: string
    """
    if auth_provider == 'facebook.com':
        return requests.get(
            f'{ate[auth_provider]}?client_id={client_id}&'
            f'redirect_uri={callback_url}&'
            f'client_secret={client_secret}&code={code}'
        ).json().get("access_token")
    elif auth_provider == 'microsoft.com':
        return requests.post(
            ate[auth_provider].replace("<tenant>", code),
            data={
                "grant_type": 'client_credentials',
                "scope": "https://graph.microsoft.com/.default",
                "redirect_uri": callback_url
            },
            auth=HTTPBasicAuth(client_id, client_secret)
        ).json().get("access_token")
    elif auth_provider == 'github.com':
        return requests.post(
            ate[auth_provider],
            data={
                "grant_type": 'authorization_code',
                "code": code,
                "redirect_uri": callback_url,
                "code_verifier": challenge_txt
            },
            headers={'Accept': 'application/json'},
            auth=HTTPBasicAuth(client_id, client_secret)
        ).json().get("access_token")
    elif is_valid_oauth_provider(auth_provider):
        return requests.post(
            ate[auth_provider],
            data={
                "grant_type": 'authorization_code',
                "code": code,
                "redirect_uri": callback_url,
                "code_verifier": challenge_txt
            },
            auth=HTTPBasicAuth(client_id, client_secret)
        ).json().get("access_token")
    else:
        return None
