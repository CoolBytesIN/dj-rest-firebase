import os

access_token_endpoints = {
    "google.com": "https://accounts.google.com/o/oauth2/token",
    "facebook.com": "https://graph.facebook.com/v11.0/oauth/access_token",
    "github.com": "https://github.com/login/oauth/access_token",
    "apple.com": "https://appleid.apple.com/auth/token",
    "microsoft.com": "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token",
    "yahoo.com": "https://api.login.yahoo.com/oauth2/get_token",
    "twitter.com": "https://api.twitter.com/2/oauth2/token"
    # "amazon.com": "https://api.amazon.com/auth/o2/token",
    # "linkedin.com": "https://www.linkedin.com/oauth/v2/accessToken",
    # "reddit.com": "https://www.reddit.com/api/v1/access_token",
}

FIREBASE_API_KEY = os.environ.get('FIREBASE_API_KEY', '')

# Reference Firebase document: https://firebase.google.com/docs/reference/rest/auth
FIREBASE_SIGNUP_EMAIL_PASSWORD = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={FIREBASE_API_KEY}"
FIREBASE_SIGNIN_EMAIL_PASSWORD = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=" \
                                 f"{FIREBASE_API_KEY}"
FIREBASE_SIGNIN_ANONYMOUSLY = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={FIREBASE_API_KEY}"
FIREBASE_FETCH_EMAIL_PROVIDERS = f"https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key=" \
                                 f"{FIREBASE_API_KEY}"
FIREBASE_SIGNIN_OAUTH = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp?key={FIREBASE_API_KEY}"
FIREBASE_EMAIL_VERIFICATION = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={FIREBASE_API_KEY}"
FIREBASE_CONFIRM_EMAIL_VERIFICATION = f"https://identitytoolkit.googleapis.com/v1/accounts:update?key=" \
                                      f"{FIREBASE_API_KEY}"
FIREBASE_DELETE_ACCOUNT = f"https://identitytoolkit.googleapis.com/v1/accounts:delete?key={FIREBASE_API_KEY}"
FIREBASE_GET_USER_DATA = f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={FIREBASE_API_KEY}"
FIREBASE_UPDATE_PROFILE = f"https://identitytoolkit.googleapis.com/v1/accounts:update?key={FIREBASE_API_KEY}"
FIREBASE_PASSWORD_RESET = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={FIREBASE_API_KEY}"
FIREBASE_VERIFY_PASSWORD_RESET_CODE = f"https://identitytoolkit.googleapis.com/v1/accounts:resetPassword?key=" \
                                      f"{FIREBASE_API_KEY}"
FIREBASE_CONFIRM_PASSWORD_RESET = f"https://identitytoolkit.googleapis.com/v1/accounts:resetPassword?key=" \
                                  f"{FIREBASE_API_KEY}"
FIREBASE_CHANGE_EMAIL = f"https://identitytoolkit.googleapis.com/v1/accounts:update?key={FIREBASE_API_KEY}"
FIREBASE_CHANGE_PASSWORD = f"https://identitytoolkit.googleapis.com/v1/accounts:update?key={FIREBASE_API_KEY}"
FIREBASE_LINK_WITH_EMAIL_PASSWORD = f"https://identitytoolkit.googleapis.com/v1/accounts:update?key={FIREBASE_API_KEY}"
FIREBASE_LINK_WITH_OAUTH = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp?key={FIREBASE_API_KEY}"
FIREBASE_UNLINK_PROVIDER = f"https://identitytoolkit.googleapis.com/v1/accounts:update?key={FIREBASE_API_KEY}"
FIREBASE_ID_TOKEN_REFRESH = f"https://securetoken.googleapis.com/v1/token?key={FIREBASE_API_KEY}"
FIREBASE_CUSTOM_TOKEN_EXCHANGE = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=" \
                                 f"{FIREBASE_API_KEY}"
