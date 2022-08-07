import pyotp
import requests
from dj_rest_firebase.views import *
import dj_rest_firebase.endpoints as ep

FIREBASE_OAUTH_CALLBACK_URL = get_default_callback_url()


def common_response(response: dict, custom_success_response=None):
    """Wrapper for common response code
    :param str response: API Response
    :param str custom_success_response: Success Response that replaces Response
    :return: a response dictionary
    :rtype: dict
    """
    # Looking for error codes in the response
    if response is not None and "error" in response:
        if "message" in response["error"]:
            return {"error": response["error"]["message"]}
        else:
            return {"error": "UNKNOWN"}

    if custom_success_response is None:
        return {"error": "NO_RESPONSE_FOUND"} if response is None else response
    else:
        return {"success": custom_success_response}


def get_mfa_secret():
    """Generate an MFA Secret Code
    :return: MFA Secret Code
    :rtype: str
    """
    return pyotp.random_base32()


def fetch_providers_for_email(email, continue_uri="https://localhost/"):
    """Fetching the providers for the Email ID
    :param str email: User's email ID
    :param str continue_uri: User's Social Redirect URL
    :return: a response dictionary (containing a list of providers)
    :rtype: dict
    """
    response = requests.post(
        ep.FIREBASE_FETCH_EMAIL_PROVIDERS,
        data={
            "identifier": email,
            "continueUri": continue_uri
        },
        headers={"Accept": "application/json"}
    ).json()

    return common_response(response)


def signup_with_email_password(email, password, mfa_secret=None, encryption_key=None, encryption_iv=None):
    """Signing Up a new user using Email and Password inputs
    :param str email: User's email ID
    :param str password: User's password
    :param str mfa_secret: Secret for MFA Authentication
    :param str encryption_key: Encryption Key provided
    :param str encryption_iv: Encryption IV provided
    :return: a response dictionary (containing idToken or error)
    :rtype: dict
    """
    response = requests.post(
        ep.FIREBASE_SIGNUP_EMAIL_PASSWORD,
        data={
            "email": email,
            "password": password,
            "returnSecureToken": True
        },
        headers={"Accept": "application/json"}
    ).json()

    is_mfa = is_mfa_enabled()
    if is_mfa and "error" not in response and "localId" in response and mfa_secret is not None:
        # Firebase signup succeeded, and requires MFA authentication
        mfa_response = add_mfa_for_new_user(response["localId"], mfa_secret, encryption_key, encryption_iv)
        if mfa_response == "SUCCESS":
            return common_response(response)
        else:
            return {"error": "MFA_SIGNUP_FAILED"}
    elif is_mfa and mfa_secret is None:
        return {"error": "MFA_SECRET_REQUIRED"}
    else:
        return common_response(response)


def signin_with_email_password(email, password, otp=None, encryption_key=None, encryption_iv=None):
    """Signing in a user using Email and Password inputs
    :param str email: User's email ID
    :param str password: User's password
    :param str otp: One Time Passcode
    :param str encryption_key: Encryption Key provided
    :param str encryption_iv: Encryption IV provided
    :return: a response dictionary (containing idToken or error)
    :rtype: dict
    """
    providers_json = fetch_providers_for_email(email, FIREBASE_OAUTH_CALLBACK_URL)
    if "allProviders" in providers_json:
        if "password" in providers_json["allProviders"]:
            response = requests.post(
                ep.FIREBASE_SIGNIN_EMAIL_PASSWORD,
                data={
                    "email": email,
                    "password": password,
                    "returnSecureToken": True
                },
                headers={"Accept": "application/json"}
            ).json()

            is_mfa = is_mfa_enabled()
            if is_mfa and "error" not in response and "localId" in response and otp is not None:
                is_otp_valid = verify_otp(response["localId"], otp, encryption_key, encryption_iv)
                if is_otp_valid:
                    return common_response(response)
                else:
                    return {"error": "INVALID_OTP"}
            else:
                return common_response(response)
        else:
            return {"warning": "AUTH_PROVIDER_NOT_FOUND", "allProviders": providers_json["allProviders"]}
    else:
        return {"error": "USER_NOT_SIGNED_UP"}


def signin_anonymously():
    """Signing in a user anonymously
    :return: a response dictionary (containing idToken or error)
    :rtype: dict
    """
    response = requests.post(
        ep.FIREBASE_SIGNIN_ANONYMOUSLY,
        data={
            "returnSecureToken": True
        },
        headers={"Accept": "application/json"}
    ).json()

    return common_response(response)


def signin_with_oauth(auth_provider, auth_code, client_id, client_secret, callback_url=FIREBASE_OAUTH_CALLBACK_URL,
                      challenge_txt=""):
    """Signing in a user using OAuth Provider
    :param str auth_provider: OAuth Provider Name
    :param str auth_code: Code returned by OAuth Provider to redirect URL
    :param str client_id: OAuth Provider Client ID
    :param str client_secret: OAuth Provider Client Secret
    :param str callback_url: OAuth Callback URL
    :param str challenge_txt: Challenge Text for some OAuth Providers such as Twitter
    :return: a response dictionary (containing idToken or error)
    :rtype: dict
    """
    if not is_valid_oauth_provider(auth_provider):
        return {"error": "INVALID_OAUTH_PROVIDER"}

    auth_token = get_oauth_token(auth_provider, auth_code, client_id, client_secret, callback_url, challenge_txt)
    post_body = f"access_token={auth_token}&providerId={auth_provider}"

    response = requests.post(
        ep.FIREBASE_SIGNIN_OAUTH,
        data={
            "requestUri": callback_url,
            "postBody": post_body,
            "returnSecureToken": True,
            "returnIdpCredential": True
        },
        headers={"Accept": "application/json"}
    ).json()

    # Looking for error codes in the response
    if "error" in response:
        if "message" in response["error"]:
            return {"error": response["error"]["message"]}
        else:
            return {"error": "UNKNOWN"}
    elif "email" not in response:
        return {"error": "OAUTH_EMAIL_NOT_FOUND"}

    providers_json = fetch_providers_for_email(response["email"], callback_url)
    if "allProviders" in providers_json:
        if auth_provider in providers_json["allProviders"]:
            return response
        else:
            return {"warning": "AUTH_PROVIDER_NOT_FOUND", "allProviders": providers_json["allProviders"]}
    else:
        return {"error": "USER_NOT_SIGNED_UP"}


def send_email_verification(id_token):
    """Send an email with verification link
    :param str id_token: Firebase Auth ID token
    :return: a response dictionary (containing success or error message)
    :rtype: dict
    """
    response = requests.post(
        ep.FIREBASE_EMAIL_VERIFICATION,
        data={
            "idToken": id_token,
            "requestType": "VERIFY_EMAIL"
        },
        headers={"Accept": "application/json"}
    ).json()

    return common_response(response, custom_success_response="VERIFICATION_EMAIL_SENT")


def confirm_email_verification(oob_code):
    """To confirm email verification
    :param str oob_code: Code from Verification Email
    :return: a response dictionary (containing certain User details)
    :rtype: dict
    """
    response = requests.post(
        ep.FIREBASE_CONFIRM_EMAIL_VERIFICATION,
        data={
            "oobCode": oob_code
        },
        headers={"Accept": "application/json"}
    ).json()

    return common_response(response)


def get_user_data(id_token):
    """Get User Data from Firebase
    :param str id_token: Firebase Auth ID token
    :return: a response dictionary (containing user data)
    :rtype: dict
    """
    response = requests.post(
        ep.FIREBASE_GET_USER_DATA,
        data={
            "idToken": id_token
        },
        headers={"Accept": "application/json"}
    ).json()

    return common_response(response)


def delete_account(id_token):
    """To delete a user account
    :param str id_token: Firebase Auth ID token
    :return: a response dictionary (containing success or error message)
    :rtype: dict
    """
    user_info = get_user_data(id_token)
    if "users" in user_info and "localId" in user_info["users"][0]:
        response = requests.post(
            ep.FIREBASE_DELETE_ACCOUNT,
            data={
                "idToken": id_token
            },
            headers={"Accept": "application/json"}
        ).json()

        is_mfa = is_mfa_enabled()
        if is_mfa and "error" not in response:
            deletion_response = delete_mfa_of_user(user_info["users"][0]["localId"])
            if deletion_response != "SUCCESS":
                return {"error": "MFA_DELETION_ERROR"}
        return common_response(response, custom_success_response="ACCOUNT_DELETED")
    else:
        return {"error": "INVALID_USER"}


def update_profile(id_token, display_name, photo_url, delete_attributes=False, delete_attributes_list=None):
    """Update user profile in Firebase
    :param str id_token: Firebase Auth ID token
    :param str display_name: User's Display Name (First Name and Last Name combined)
    :param str photo_url: User's Photo URL
    :param str delete_attributes: Flag that indicates whether any attributes need to be deleted
    :param str delete_attributes_list: List of attributes to delete (Acceptable: 'DISPLAY_NAME' and 'PHOTO_URL')
    :return: a response dictionary (containing user data or error message)
    :rtype: dict
    """
    if delete_attributes:
        # Getting list of attributes to delete
        if delete_attributes_list is None:
            return {"error": "DELETE_ATTRIBUTES_MISSING"}
        elif isinstance(delete_attributes_list, list):
            # Acceptable list values: ['DISPLAY_NAME', 'PHOTO_URL']
            response = requests.post(
                ep.FIREBASE_UPDATE_PROFILE,
                data={
                    "idToken": id_token,
                    "displayName": display_name,
                    "photoUrl": photo_url,
                    "deleteAttribute": delete_attributes_list,
                    "returnSecureToken": True
                },
                headers={"Accept": "application/json"}
            ).json()
        else:
            return {"error": "DELETE_ATTRIBUTES_INVALID"}
    else:
        response = requests.post(
            ep.FIREBASE_UPDATE_PROFILE,
            data={
                "idToken": id_token,
                "displayName": display_name,
                "photoUrl": photo_url,
                "returnSecureToken": True
            },
            headers={"Accept": "application/json"}
        ).json()

    return common_response(response)


def send_password_reset_email(email):
    """Email password reset link
    :param str email: User's Email
    :return: a response dictionary (containing success or error message)
    :rtype: dict
    """
    response = requests.post(
        ep.FIREBASE_PASSWORD_RESET,
        data={
            "email": email,
            "requestType": "PASSWORD_RESET"
        },
        headers={"Accept": "application/json"}
    ).json()

    return common_response(response, custom_success_response="PASSWORD_RESET_EMAIL_SENT")


def verify_password_reset_code(oob_code):
    """Verify code from password reset Email
    :param str oob_code: Code from Password Reset Email
    :return: a response dictionary (containing success or error message)
    :rtype: dict
    """
    response = requests.post(
        ep.FIREBASE_VERIFY_PASSWORD_RESET_CODE,
        data={
            "oobCode": oob_code
        },
        headers={"Accept": "application/json"}
    ).json()

    return common_response(response, custom_success_response="PASSWORD_RESET_CODE_VALID")


def confirm_password_reset(oob_code, new_password):
    """Confirm password reset
    :param str oob_code: Code from Password Reset Email
    :param str new_password: User's new password
    :return: a response dictionary (containing success or error message)
    :rtype: dict
    """
    response = requests.post(
        ep.FIREBASE_CONFIRM_PASSWORD_RESET,
        data={
            "oobCode": oob_code,
            "newPassword": new_password
        },
        headers={"Accept": "application/json"}
    ).json()

    return common_response(response, custom_success_response="PASSWORD_RESET_DONE")


def change_email(id_token, new_email):
    """Change User's Email
    :param str id_token: Firebase Auth ID token
    :param str new_email: User's new Email ID
    :return: a response dictionary (containing new ID Token)
    :rtype: dict
    """
    response = requests.post(
        ep.FIREBASE_CHANGE_EMAIL,
        data={
            "idToken": id_token,
            "email": new_email,
            "returnSecureToken": True
        },
        headers={"Accept": "application/json"}
    ).json()

    return common_response(response)


def change_password(id_token, new_password):
    """Change User's Password
    :param str id_token: Firebase Auth ID token
    :param str new_password: User's new password
    :return: a response dictionary (containing new ID Token)
    :rtype: dict
    """
    response = requests.post(
        ep.FIREBASE_CHANGE_PASSWORD,
        data={
            "idToken": id_token,
            "password": new_password,
            "returnSecureToken": True
        },
        headers={"Accept": "application/json"}
    ).json()

    return common_response(response)


def change_mfa_secret(id_token, mfa_secret, encryption_key, encryption_iv):
    """Change User's MFA Secret
    :param str id_token: Firebase Auth ID token
    :param str mfa_secret: User's new MFA Secret
    :param str encryption_key: Encryption Key provided
    :param str encryption_iv: Encryption IV provided
    :return: a response dictionary (containing new ID Token)
    :rtype: dict
    """
    is_mfa = is_mfa_enabled()
    if is_mfa:
        user_info = get_user_data(id_token)
        if "users" in user_info and "localId" in user_info["users"][0]:
            update_response = update_mfa_of_user(user_info["users"][0]["localId"], mfa_secret, encryption_key,
                                                 encryption_iv)
            if update_response == "SUCCESS":
                return {"success": "MFA_UPDATED"}
            else:
                return {"error": "MFA_UPDATE_ERROR"}
        else:
            return {"error": "INVALID_USER"}
    else:
        return {"error": "MFA_NOT_ENABLED"}


def link_with_email_password(id_token, email, new_password, mfa_secret=None, encryption_key=None, encryption_iv=None):
    """Link User Account with Email/Password
    :param str id_token: Firebase Auth ID token
    :param str email: User's Email ID
    :param str new_password: User's new password
    :param str mfa_secret: Secret for MFA Authentication
    :param str encryption_key: Encryption Key provided
    :param str encryption_iv: Encryption IV provided
    :return: a response dictionary (containing new ID Token)
    :rtype: dict
    """
    response = requests.post(
        ep.FIREBASE_LINK_WITH_EMAIL_PASSWORD,
        data={
            "idToken": id_token,
            "email": email,
            "password": new_password,
            "returnSecureToken": True
        },
        headers={"Accept": "application/json"}
    ).json()

    is_mfa = is_mfa_enabled()
    if is_mfa and "error" not in response and "localId" in response and mfa_secret is not None:
        # Firebase signup succeeded, and requires MFA authentication
        mfa_response = add_or_update_mfa_of_user(response["localId"], mfa_secret, encryption_key, encryption_iv)
        if mfa_response == "SUCCESS":
            return common_response(response)
        else:
            return {"error": "MFA_LINK_FAILED"}
    else:
        return common_response(response)


def link_with_oauth(id_token, auth_provider, auth_code, client_id, client_secret,
                    callback_url=FIREBASE_OAUTH_CALLBACK_URL, challenge_txt=""):
    """Link User Account with an OAuth provider
    :param str id_token: Firebase Auth ID token
    :param str auth_provider: OAuth Provider Name
    :param str auth_code: Code returned by OAuth Provider to redirect URL
    :param str client_id: OAuth Provider Client ID
    :param str client_secret: OAuth Provider Client Secret
    :param str callback_url: OAuth Redirect URL
    :param str challenge_txt: Challenge Text for some OAuth Providers such as Twitter
    :return: a response dictionary (containing new ID Token)
    :rtype: dict
    """
    if not is_valid_oauth_provider(auth_provider):
        return {"error": "INVALID_OAUTH_PROVIDER"}

    auth_token = get_oauth_token(auth_provider, auth_code, client_id, client_secret, callback_url, challenge_txt)
    if auth_provider == "google.com":
        post_body = f"id_token={auth_token}&providerId={auth_provider}"
    else:
        post_body = f"access_token={auth_token}&providerId={auth_provider}"

    response = requests.post(
        ep.FIREBASE_LINK_WITH_OAUTH,
        data={
            "idToken": id_token,
            "postBody": post_body,
            "requestUri": callback_url,
            "returnSecureToken": True,
            "returnIdpCredential": True
        },
        headers={"Accept": "application/json"}
    ).json()

    return common_response(response)


def unlink_provider(id_token, auth_provider):
    """Unlink User Account from an Auth provider
    :param str id_token: Firebase Auth ID token
    :param str auth_provider: OAuth Provider Name
    :return: a response dictionary (containing some user info)
    :rtype: dict
    """
    if not is_valid_auth_provider(auth_provider):
        return {"error": "INVALID_AUTH_PROVIDER"}

    response = requests.post(
        ep.FIREBASE_UNLINK_PROVIDER,
        data={
            "idToken": id_token,
            "deleteProvider": auth_provider
        },
        headers={"Accept": "application/json"}
    ).json()

    return common_response(response)


def refresh_id_token(refresh_token):
    """Generate a new ID token using Refresh token
    :param str refresh_token: Firebase Auth Refresh token
    :return: a response dictionary (containing new ID token)
    :rtype: dict
    """
    response = requests.post(
        ep.FIREBASE_ID_TOKEN_REFRESH,
        data={
            "refresh_token": refresh_token,
            "grant_type": "refresh_token"
        },
        headers={"Accept": "application/json"}
    ).json()

    return common_response(response)


def exchange_custom_token_for_id_token(custom_token):
    """Exchange custom token for ID and Refresh tokens
    :param str custom_token: Firebase Auth Custom token
    :return: a response dictionary (containing ID and Refresh tokens)
    :rtype: dict
    """
    response = requests.post(
        ep.FIREBASE_CUSTOM_TOKEN_EXCHANGE,
        data={
            "token": custom_token,
            "returnSecureToken": True
        },
        headers={"Accept": "application/json"}
    ).json()

    return common_response(response)
