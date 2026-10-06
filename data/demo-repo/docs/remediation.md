# Remediation playbook

**Do not only delete a leaked secret.**

1. Revoke the credential at the provider.
2. Rotate to a replacement.
3. Remove the secret from current source.
4. Review git history and CI logs.
5. Confirm the old credential is unusable.
6. Mark the finding VERIFIED.
