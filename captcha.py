"""Server-side Turnstile verification for token submissions."""
from datetime import datetime, timezone
import requests


def verify(token, secret, allowed_hostnames=()):
    if not secret:
        return False, 'CAPTCHA is not configured. Please contact support.'
    if not token or len(token) > 2048:
        return False, 'Please complete the CAPTCHA before submitting.'
    try:
        response = requests.post(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            data={'secret': secret, 'response': token}, timeout=10)
        response.raise_for_status()
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError('Invalid response')
        if result.get('success') is not True or result.get('action') != 'token_submission':
            return False, 'CAPTCHA verification failed. Complete a new challenge.'
        if allowed_hostnames and result.get('hostname') not in allowed_hostnames:
            return False, 'CAPTCHA verification failed for this hostname.'
        timestamp = result.get('challenge_ts')
        if not isinstance(timestamp, str):
            raise ValueError('Missing timestamp')
        issued = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        age = (datetime.now(timezone.utc) - issued).total_seconds()
        if not 0 <= age < 60:
            return False, 'CAPTCHA expired. Complete a new challenge and submit within 1 minute.'
    except (requests.RequestException, ValueError, TypeError):
        return False, 'CAPTCHA verification is unavailable. Please try again.'
    return True, ''
