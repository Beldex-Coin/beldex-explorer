from explorer import config

# Local settings.  Changes to this file are meant for a local installation (and should not be
# committed to git).

# Example config override:
#config.blocks_per_page = 10

# Must match the admin portal's INGEST_API_KEY (beldex-asset-admin-portal/.env)
# exactly, or every /assets/submit POST gets 401'd by the admin portal.
config.token_submit_api_key = None

# Must match the admin portal's TOKEN_VERIFY_SECRET (same .env) exactly, or
# every ownership challenge this explorer issues will fail the admin portal's
# independent re-verification even when the signature is genuinely valid.
config.token_verify_secret = None

