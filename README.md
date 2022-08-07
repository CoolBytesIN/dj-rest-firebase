# Firebase for Django Rest Framework

🎉 This package is for those who want to avoid vendor lock-in with Firebase, but still use it for authentication in their DRF project.  🎉

Some features:
* Firebase Authentication APIs.
* Sign in with OAuth Providers.
* Multi-factor authentication (MFA) for Email/Password provider.
* No vendor lock-in, more control to the Developer.

> **Currently, OAuth is working only with Google, Facebook and GitHub 😢**

---

## Installation

You can install the [package from PyPI](https://pypi.org/project/dj-rest-firebase/) by running the following command:

```sh
pip install dj-rest-firebase
```

---

## Initial Setup

### Firebase Setup

* Create a Firebase project and then a web app inside the Firebase project. Make a note of the **Web API Key** available under **Project Settings ➡ General** tab. You'll need this in [Django Setup](https://github.com/CoolBytesIN/dj-rest-firebase/blob/main/README.md#django-setup).
  * _There are many articles on the web that explain how to create a Firebase project and an app inside it._
* Navigate to **Build ➡ Authentication ➡ Sign-in method** and add/enable your preferred providers.
  * _There are many articles on the web that explain how to generate Client ID and Client Secret for each OAuth provider._
  * **_NOTE_**: In case of Google provider, the Client ID and Client Secret are available under "Web SDK Configuration".
  * **_NOTE_**: Without this setup, you'll not be able to use Firebase authentication. You'll need to have at-least one provider added.
* Navigate to **Build ➡ Authentication ➡ Settings** and customize **User Account Management** settings to your preference.
* Also, under the same **Settings** tab, modify **Authorized Domains**.
* **OPTIONAL**: Change Email templates under **Build ➡ Authentication ➡ Templates** tab. This tab defines which Email ID to use for sending emails such as verification links etc. and how the Email template looks like.
  * **_NOTE_**: The Email ID can be configured under **SMTP Settings** option.

### Django Setup

* Add this package to **INSTALLED_APPS** list in `settings.py` file.
```python
INSTALLED_APPS = [
    ...,
    'dj_rest_firebase'
]
```
* Also set the following attributes in `settings.py` file.
  * **_NOTE_**: `DRF_MFA_ENABLED` is OPTIONAL and add it only if you need multi-factor authentication (MFA).
  * **_NOTE_**: `DRF_OAUTH_CALLBACK_URL` will be used only if you don't pass a callback URL explicitly in certain functions (see Functions usage below). This setting is useful when your callback URL is same for all OAuth providers.
```python
DRF_MFA_ENABLED = True
DRF_OAUTH_CALLBACK_URL = "https://<YOUR CALLBACK URL HERE>/"
```
* Create an environment variable named `FIREBASE_API_KEY` and set it to the **Web API Key** value taken from [Firebase Setup](https://github.com/CoolBytesIN/dj-rest-firebase/blob/main/README.md#firebase-setup) above.
* Run Django migration commands:
  * This should create a Django model called `FirebaseMFASecret`.
  * This model will be unused if MFA is not enabled.
```sh
python manage.py makemigrations
python manage.py migrate
```

### Final Setup

> _**This setup is OPTIONAL if you don't have multi-factor authentication enabled.**_

* Create two 16-character (16 or more) strings and store them in files safely.
* Use these strings as replacements for `encryption_key` and `encryption_iv` respectively in the functions.
  * **NOTE**: These keys are used for encrypting the MFA Secrets before saving them in the Django model, as an added security.
  * **NOTE**: The same keys are used to de-crypt the encrypted secrets from Django model.

> **Caution: If you lose these keys, the email/password authentication will not work for any user.**

---

## Release Notes

| Version         | Release Date   | Details                                               |
|-----------------|----------------|-------------------------------------------------------|
| 0.6.6 (Current) | August 2022    | Firebase Auth APIs                                    |
| 0.7.5           | XYZ 202X       | Support for Twitter, Yahoo, Microsoft and Apple OAuth |
| Future          | XYZ 202X       | Firebase Storage & Firestore APIs                     |

---

## Functions Usage

> **Before you use these functions, it's very important that you review the [Things to Consider](https://github.com/CoolBytesIN/dj-rest-firebase/blob/main/README.md#things-to-consider) section below to keep your application secure.**

###### Usage Example

**_\*\*All functions are available from `dj_rest_firebase.auth`\*\*_**

```py
from dj_rest_firebase.auth import fetch_providers_for_email


print(str(fetch_providers_for_email("user@example.com")))
```

<br />

### get_mfa_secret()

**Purpose**: To generate an MFA Secret code

**Inputs**: `No Input Required`

**Response**:

```py
'[MFA_SECRET]'
```

<br />

### fetch_providers_for_email()

**Purpose**: To fetch the auth providers info for an Email ID

**Inputs**:
* `email`: User's Email ID.
* (Optional) `continue_uri`: The URI to which the IDP redirects the user back. For this use case, this is just the current URL.

**Response**:

```py
{
  'kind': 'identitytoolkit#CreateAuthUriResponse',
  'allProviders': ['password'],
  'registered': True,
  'sessionId': '[SESSION_ID]',
  'signinMethods': ['password']
}
```

<br />

### signup_with_email_password()

**Purpose**: To sign up a new user using Email and Password

**Inputs**:
* `email`: User's Email ID.
* `password`: User's Password.
* (Optional) `mfa_secret`: MFA Secret code. This is required if `DRF_MFA_ENABLED` is set to `True`.
* (Optional) `encryption_key`: Encryption Key created in [Final Setup](https://github.com/CoolBytesIN/dj-rest-firebase/blob/main/README.md#final-setup) above. This is required if `DRF_MFA_ENABLED` is set to `True`.
* (Optional) `encryption_iv`: Encryption IV created in [Final Setup](https://github.com/CoolBytesIN/dj-rest-firebase/blob/main/README.md#final-setup) above. This is required if `DRF_MFA_ENABLED` is set to `True`.

**Response**:

```py
{
  "idToken": "[ID_TOKEN]",
  "email": "[USER_EMAIL]",
  "refreshToken": "[REFRESH_TOKEN]",
  "expiresIn": "3600",
  "localId": "[USER_ID]"
}
```

<br />

### signin_with_email_password()

**Purpose**: To sign in a user using Email and Password

**Inputs**:
* `email`: User's Email ID.
* `password`: User's Password.
* (Optional) `otp`: One Time Passcode (String). This is required if `DRF_MFA_ENABLED` is set to `True`.
* (Optional) `encryption_key`: Encryption Key created in [Final Setup](https://github.com/CoolBytesIN/dj-rest-firebase/blob/main/README.md#final-setup) above. This is required if `DRF_MFA_ENABLED` is set to `True`.
* (Optional) `encryption_iv`: Encryption IV created in [Final Setup](https://github.com/CoolBytesIN/dj-rest-firebase/blob/main/README.md#final-setup) above. This is required if `DRF_MFA_ENABLED` is set to `True`.

**Response**:

```py
{
  "localId": "[USER_ID]",
  "email": "[USER_EMAIL]",
  "displayName": "",
  "idToken": "[ID_TOKEN]",
  "registered": True,
  "refreshToken": "[REFRESH_TOKEN]",
  "expiresIn": "3600"
}
```

<br />

### signin_anonymously()

**Purpose**: To sign in anonymously

**Inputs**: `No Input Required`

**Response**:

```py
{
  "idToken": "[ID_TOKEN]",
  "email": "",
  "refreshToken": "[REFRESH_TOKEN]",
  "expiresIn": "3600",
  "localId": "[USER_ID]"
}
```

<br />

### signin_with_oauth()

**Purpose**: To sign in a user using OAuth Provider

**Inputs**:
* `auth_provider`: OAuth provider name.
* `auth_code`: Authorization code returned to the Callback URL by the [links from this table below](https://github.com/CoolBytesIN/dj-rest-firebase/blob/main/README.md#oauth-authorize-sign-in-links).
* `client_id`: OAuth Provider Client ID.
* `client_secret`: OAuth Provider Client Secret.
* (Optional) `callback_url`: OAuth callback URL. This is REQUIRED if `DRF_OAUTH_CALLBACK_URL` is not set.
* (Optional) `challenge_txt`: This is required only when OAuth Provider is `twitter.com`. This value should match `<CHALLENGE_TEXT>` from [this table below](https://github.com/CoolBytesIN/dj-rest-firebase/blob/main/README.md#oauth-authorize-sign-in-links).

**Response**:

```py
{
  "federatedId": "https://accounts.google.com/1234567890",
  "providerId": "google.com",
  "localId": "[USER_ID]",
  "emailVerified": True,
  "email": "[USER_EMAIL]",
  "oauthIdToken": "[GOOGLE_ID_TOKEN]",
  "firstName": "John",
  "lastName": "Doe",
  "fullName": "John Doe",
  "displayName": "John Doe",
  "idToken": "[ID_TOKEN]",
  "photoUrl": "https://lh5.googleusercontent.com/.../photo.jpg",
  "refreshToken": "[REFRESH_TOKEN]",
  "expiresIn": "3600",
  "rawUserInfo": "{\"updated_time\":\"2017-02-22T01:10:57+0000\",\"gender\":\"male\", ...}"
}
```

<br />

### send_email_verification()

**Purpose**: To send an email with verification link

**Inputs**:
* `id_token`: Firebase Auth ID token.

**Response**:

```py
{
  "success": "VERIFICATION_EMAIL_SENT"
}
```

<br />

### confirm_email_verification()

**Purpose**: To confirm email verification

**Inputs**:
* `oob_code`: Code from Verification Email.

**Response**:

```py
{
  "localId": "[USER_ID]",
  "email": "[USER_EMAIL]",
  "passwordHash": "...",
  "providerUserInfo": [
    {
      "providerId": "password",
      "federatedId": "[USER_EMAIL]"
    }
  ]
}
```

<br />

### get_user_data()

**Purpose**: To get user data from Firebase

**Inputs**:
* `id_token`: Firebase Auth ID token.

**Response**:

```py
{
  "users": [
    {
      "localId": "[USER_ID]",
      "email": "[USER_EMAIL]",
      "emailVerified": False,
      "displayName": "John Doe",
      "providerUserInfo": [
        {
          "providerId": "password",
          "displayName": "John Doe",
          "photoUrl": "http://localhost:8080/img1234567890/photo.png",
          "email": "[USER_EMAIL]",
        }
      ],
      "photoUrl": "https://lh5.googleusercontent.com/.../photo.jpg",
      "passwordHash": "...",
      "passwordUpdatedAt": 1.484124177E12,
      "validSince": "1484124177",
      "disabled": False,
      "lastLoginAt": "1484628946000",
      "createdAt": "1484124142000",
      "customAuth": False
    }
  ]
}
```

<br />

### delete_account()

**Purpose**: To delete a user account

**Inputs**:
* `id_token`: Firebase Auth ID token.

**Response**:

```py
{
  "success": "ACCOUNT_DELETED"
}
```

<br />

### update_profile()

**Purpose**: To delete a user account

**Inputs**:
* `id_token`: Firebase Auth ID token.
* `display_name`: User's Display Name (First Name and Last Name combined).
* `photo_url`: User's Photo URL.
* (Optional) `delete_attributes`: (bool) Flag to indicate whether to delete any attributes.
* (Optional) `delete_attributes_list`: (list) List of attributes to delete. Acceptable list values: 'DISPLAY_NAME', 'PHOTO_URL'.

**Response**:

```py
{
  "localId": "[USER_ID]",
  "email": "[USER_EMAIL]",
  "displayName": "John Doe",
  "photoUrl": "[http://localhost:8080/img1234567890/photo.png]",
  "passwordHash": "...",
  "providerUserInfo": [
    {
      "providerId": "password",
      "federatedId": "[USER_EMAIL]",
      "displayName": "John Doe",
      "photoUrl": "http://localhost:8080/img1234567890/photo.png"
    }
  ],
  "idToken": "[NEW_ID_TOKEN]",
  "refreshToken": "[NEW_REFRESH_TOKEN]",
  "expiresIn": "3600"
}
```

<br />

### send_password_reset_email()

**Purpose**: To Email password reset link

**Inputs**:
* `email`: User Email ID.

**Response**:

```py
{
  "success": "PASSWORD_RESET_EMAIL_SENT"
}
```

<br />

### verify_password_reset_code()

**Purpose**: To verify code from password reset Email

**Inputs**:
* `oob_code`: Code from Password Reset Email.

**Response**:

```py
{
  "success": "PASSWORD_RESET_CODE_VALID"
}
```

<br />

### confirm_password_reset()

**Purpose**: To confirm password reset

**Inputs**:
* `oob_code`: Code from Password Reset Email.
* `new_password`: User's new password.

**Response**:

```py
{
  "success": "PASSWORD_RESET_DONE"
}
```

<br />

### change_email()

**Purpose**: To change User's Email

**Inputs**:
* `id_token`: Firebase Auth ID token.
* `new_email`: User's new Email ID.

**Response**:

```py
{
  "localId": "[USER_ID]",
  "email": "[USER_EMAIL]",
  "passwordHash": "...",
  "providerUserInfo": [
    {
      "providerId": "password",
      "federatedId": "[USER_EMAIL]"
    }
  ],
  "idToken": "[NEW_ID_TOKEN]",
  "refreshToken": "[NEW_REFRESH_TOKEN]",
  "expiresIn": "3600"
}
```

<br />

### change_password()

**Purpose**: To change User's Password

**Inputs**:
* `id_token`: Firebase Auth ID token.
* `new_password`: User's new password.

**Response**:

```py
{
  "localId": "[USER_ID]",
  "email": "[USER_EMAIL]",
  "passwordHash": "...",
  "providerUserInfo": [
    {
      "providerId": "password",
      "federatedId": "[USER_EMAIL]"
    }
  ],
  "idToken": "[NEW_ID_TOKEN]",
  "refreshToken": "[NEW_REFRESH_TOKEN]",
  "expiresIn": "3600"
}
```

<br />

### change_mfa_secret()

**Purpose**: To change User's MFA Secret

**Inputs**:
* `id_token`: Firebase Auth ID token.
* `mfa_secret`: MFA Secret code.
* `encryption_key`: Encryption Key created in [Final Setup](https://github.com/CoolBytesIN/dj-rest-firebase/blob/main/README.md#final-setup) above.
* `encryption_iv`: Encryption IV created in [Final Setup](https://github.com/CoolBytesIN/dj-rest-firebase/blob/main/README.md#final-setup) above.

**Response**:

```py
{
  "success": "MFA_UPDATED"
}
```

<br />

### link_with_email_password()

**Purpose**: To link user account with Email/Password

**Inputs**:
* `id_token`: Firebase Auth ID token.
* `email`: User's Email ID.
* `new_password`: User's new password.
* (Optional) `mfa_secret`: MFA Secret code. This is required if `DRF_MFA_ENABLED` is set to `True`.
* (Optional) `encryption_key`: Encryption Key created in [Final Setup](https://github.com/CoolBytesIN/dj-rest-firebase/blob/main/README.md#final-setup) above. This is required if `DRF_MFA_ENABLED` is set to `True`.
* (Optional) `encryption_iv`: Encryption IV created in [Final Setup](https://github.com/CoolBytesIN/dj-rest-firebase/blob/main/README.md#final-setup) above. This is required if `DRF_MFA_ENABLED` is set to `True`.

**Response**:

```py
{
  "localId": "[USER_ID]",
  "email": "[USER_EMAIL]",
  "displayName": "John Doe",
  "photoUrl": "https://lh5.googleusercontent.com/.../photo.jpg",
  "passwordHash": "...",
  "providerUserInfo": [
    {
      "providerId": "password",
      "federatedId": "[USER_EMAIL]"
    }
  ],
  "idToken": "[ID_TOKEN]",
  "refreshToken": "[REFRESH_TOKEN]",
  "expiresIn": "3600",
  "emailVerified": False
}
```

<br />

### link_with_oauth()

**Purpose**: To link user account with an OAuth provider

**Inputs**:
* `id_token`: Firebase Auth ID token.
* `auth_provider`: OAuth provider name.
* `auth_code`: Authorization code returned to the Callback URL by the [links from this table below](https://github.com/CoolBytesIN/dj-rest-firebase/blob/main/README.md#oauth-authorize-sign-in-links).
* `client_id`: OAuth Provider Client ID.
* `client_secret`: OAuth Provider Client Secret.
* (Optional) `callback_url`: OAuth callback URL. This is REQUIRED if `DRF_OAUTH_CALLBACK_URL` is not set.
* (Optional) `challenge_txt`: This is required only when OAuth Provider is `twitter.com`. This value should match `<CHALLENGE_TEXT>` from [this table below](https://github.com/CoolBytesIN/dj-rest-firebase/blob/main/README.md#oauth-authorize-sign-in-links).

**Response**:

```py
{
  "federatedId": "https://accounts.google.com/1234567890",
  "providerId": "google.com",
  "localId": "[USER_ID]",
  "emailVerified": True,
  "email": "[USER_EMAIL]",
  "oauthIdToken": "[GOOGLE_ID_TOKEN]",
  "firstName": "John",
  "lastName": "Doe",
  "fullName": "John Doe",
  "displayName": "John Doe",
  "idToken": "[ID_TOKEN]",
  "photoUrl": "https://lh5.googleusercontent.com/.../photo.jpg",
  "refreshToken": "[REFRESH_TOKEN]",
  "expiresIn": "3600",
  "rawUserInfo": "{\"updated_time\":\"2017-02-22T01:10:57+0000\",\"gender\":\"male\", ...}"
}
```

<br />

### unlink_provider()

**Purpose**: To unlink User Account from an Auth provider

**Inputs**:
* `id_token`: Firebase Auth ID token.
* `auth_provider`: OAuth provider name.

**Response**:

```py
{
  "localId": "[USER_ID]",
  "email": "[USER_EMAIL]",
  "displayName": "John Doe",
  "photoUrl": "https://lh5.googleusercontent.com/.../photo.jpg",
  "passwordHash": "...",
  "providerUserInfo": [
    {
      "providerId": "google.com",
      "federatedId": "1234567890",
      "displayName": "John Doe",
      "photoUrl": "https://lh5.googleusercontent.com/.../photo.jpg"
    },
    {
      "providerId": "password",
      "federatedId": "[USER_EMAIL]"
    }
  ],
  "emailVerified": "true"
}
```

<br />

### refresh_id_token()

**Purpose**: To generate a new ID token using Refresh token

**Inputs**:
* `refresh_token`: Firebase Auth Refresh token.

**Response**:

```py
{
  "expires_in": "3600",
  "token_type": "Bearer",
  "refresh_token": "[REFRESH_TOKEN]",
  "id_token": "[ID_TOKEN]",
  "user_id": "[USER_ID]",
  "project_id": "1234567890"
}
```

<br />

### exchange_custom_token_for_id_token()

**Purpose**: To exchange custom token for ID and Refresh tokens

**Inputs**:
* `custom_token`: Firebase Auth Custom token.

**Response**:

```py
{
  "idToken": "[ID_TOKEN]",
  "refreshToken": "[REFRESH_TOKEN]",
  "expiresIn": "3600"
}
```

---

## Things to Consider

### Response Codes

All functions return a dictionary with one of the following keys (and a code as their value), in case of un-successful operations:
* error
  * _Indicates failed operation_
* warning
  * _This is not really an error but something to be taken care of by the application. The only possible code for this is AUTH_PROVIDER_NOT_FOUND. See below on what this means._

###### AUTH_PROVIDER_NOT_FOUND

If you're getting this response, it means that the user is trying to sign in using a provider that they didn't previously link.

For example, if the user signed up using Email/Password initially, but later trying to sign in using Google provider (with same Email ID).
Another example, if the user signed up using Facebook provider, but later trying to sign in using GitHub provider.

In order to allow the user to perform above actions, they need to first link their providers while being signed in. That is, in the first example above, they should first sign in using Email/Password and then link Google provider, in order to use it for signing-in in the future.

###### ADMIN_ONLY_OPERATION

This `error` code indicates that some firebase configuration is not done or incomplete.

For example, you may receive this error when you try to use the function `signin_anonymously()`. Here, it indicates that the Anonymous provider is not enabled in Firebase.

### emailVerified Boolean

When you call `signup_with_email_password` function or `signin_with_oauth` function, it returns an `id_token` in the success response. However, the `emailVerified` attribute may be returned as `False`.

It's very important that the email gets verified, before letting the user access any sensitive information. Not doing so can make your application insecure.

> **_`signin_with_oauth` always returns `emailVerified` as `True` when the auth provider is 'google.com'_** 

### QR Code Generator (for MFA Secret)

The following link can be used to generate QR Code image, using the MFA Secret. Replace `<MFA_SECRET>` and `<ACCOUNT_NAME>`.

https://chart.apis.google.com/chart?cht=qr&chs=250x250&chld=L|2&chl=otpauth://totp/<ACCOUNT_NAME>?secret=<MFA_SECRET>

### OAuth Authorize (Sign In) Links

You can use following links in your frontend application to sign in with OAuth provider. Replace `<CLIENT_ID>`, `<CALLBACK_URL>` and `<YOUR_STATE>`.
* `<CLIENT_ID>` is your OAuth provider's client id.
* `<CALLBACK_URL>` is the callback URL set in your OAuth app settings.
* `<YOUR_STATE>` is some state that needs to be persisted in the callback URL.
* `<CHALLENGE_TEXT>` is required only for Twitter.

| OAuth Provider | Authorize Link                                                                                                                                                                                                               |
|----------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Google         | `https://accounts.google.com/o/oauth2/auth/oauthchooseaccount?prompt=select_account&client_id=<CLIENT_ID>&redirect_uri=<CALLBACK_URL>&scope=profile%20email&response_type=code&flowName=GeneralOAuthFlow&state=<YOUR_STATE>` |
| Facebook       | `https://www.facebook.com/v14.0/dialog/oauth?client_id=<CLIENT_ID>&redirect_uri=<CALLBACK_URL>&scope=email&auth_type=rerequest&state=<YOUR_STATE>`                                                                           |
| GitHub         | `https://github.com/login/oauth/authorize?login&client_id=<CLIENT_ID>&redirect_uri=<CALLBACK_URL>&scope=user&state=<YOUR_STATE>`                                                                                             |
| Microsoft      | `https://login.microsoftonline.com/common/adminconsent?client_id=<CLIENT_ID>&redirect_uri=<CALLBACK_URL>&state=<YOUR_STATE>`                                                                                                 |
| Apple          | `https://appleid.apple.com/auth/authorize?response_type=code id_token&response_mode=form_post&client_id=<CLIENT_ID>&scope=name email&redirect_uri=<CALLBACK_URL>&state=<YOUR_STATE>`                                         |
| Yahoo          | `https://api.login.yahoo.com/oauth2/request_auth?client_id=<CLIENT_ID>&response_type=code&redirect_uri=<CALLBACK_URL>&scope=openid&state=<YOUR_STATE>`                                                                       |
| Twitter        | `https://twitter.com/i/oauth2/authorize?response_type=code&client_id=<CLIENT_ID>&redirect_uri=<CALLBACK_URL>&scope=offline.access&state=<YOUR_STATE>&code_challenge=<CHALLENGE_TEXT>&code_challenge_method=plain`            |
| Amazon         | `https://www.amazon.com/ap/oa?client_id=<CLIENT_ID>&scope=profile&response_type=code&redirect_uri=<CALLBACK_URL>&state=<YOUR_STATE>`                                                                                         |
| LinkedIn       | `https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=<CLIENT_ID>&redirect_uri=<CALLBACK_URL>&scope=r_liteprofile%20r_emailaddress&state=<YOUR_STATE>`                                               |
| Reddit         | `https://www.reddit.com/api/v1/authorize?response_type=code&client_id=<CLIENT_ID>&redirect_uri=<CALLBACK_URL>&scope=identity&state=<YOUR_STATE>`                                                                             |

---

## Help

If you run into any issues while setting up or while using the package, feel free to open an issue in this GitHub repository.

_This is my first PyPI package and I built it from scratch. If you like my work, please consider giving it a GitHub ⭐️️. Thanks!_