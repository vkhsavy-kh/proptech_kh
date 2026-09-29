-- Session invalidation on password change.
--
-- Without this, changing a password leaves every previously issued session
-- valid, so an attacker holding a stolen cookie keeps access after the owner
-- rotates their credentials. Each session records the epoch it was minted
-- under; bumping the column retires all of them at once, with no need to
-- enumerate or delete individual KV entries.
ALTER TABLE users ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 0;
