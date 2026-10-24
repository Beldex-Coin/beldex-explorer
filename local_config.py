import os

from explorer import config

# Local settings.  Changes to this file are meant for a local installation (and should not be
# committed to git).

# Example config override:
#config.blocks_per_page = 10

# NOTE: this file is tracked by git, so no secret may be written here as a
# literal. The real values live in local_secrets.py (untracked) or in the
# environment; both are read below.
try:
    import local_secrets
except ImportError:
    local_secrets = None


def _secret(name):
    """local_secrets.<name>, else the <name> environment variable, else None."""
    value = getattr(local_secrets, name, None) if local_secrets else None
    return value or os.environ.get(name) or None


# Must match the admin portal's INGEST_API_KEY (beldex-asset-admin-portal/.env)
# exactly, or every /tokens/submit POST gets 401'd by the admin portal.
config.token_submit_api_key = _secret('TOKEN_SUBMIT_API_KEY')

# Must match the admin portal's TOKEN_VERIFY_SECRET (same .env) exactly, or
# every ownership challenge this explorer issues will fail the admin portal's
# independent re-verification even when the signature is genuinely valid.
config.token_verify_secret = _secret('TOKEN_VERIFY_SECRET')

# Cloudflare Turnstile secret for /tokens/submit (the site key is public and
# stays in config.py).
config.captcha_secret_key = _secret('CAPTCHA_SECRET_KEY') or ''
