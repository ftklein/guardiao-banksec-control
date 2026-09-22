// Public, non-sensitive constants of the BankSec control plane.
//
// This module must never hold a token, a private URL, a secret or any
// operational configuration: every value here is safe to publish and is
// already public by virtue of living in this repository.

export const TARGET_OWNER = 'ftklein';
export const TARGET_REPOSITORY = 'GuardiaoSystem';
export const STATUS_CONTEXT = 'banksec/trusted-gate';

// The trust surface is closed and complete: an ACTIVE manifest must pin
// exactly these four files, no more and no fewer.
export const TRUSTED_PATHS = Object.freeze([
  'security/banksec/security-cycle.sh',
  'security/banksec/ci-review.md',
  'security/banksec/baseline.md',
  'security/banksec/postgres-banksec-readonly.sql'
]);
