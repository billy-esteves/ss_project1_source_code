CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_disabled BOOLEAN DEFAULT FALSE,
    is_admin BOOLEAN DEFAULT FALSE,
    bad_attempts INT DEFAULT 0,
    locked_until TIMESTAMP DEFAULT NULL
);

CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    owner_id INTEGER REFERENCES users(id),
    title TEXT NOT NULL,
    filename TEXT NOT NULL,
    metadata TEXT,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE document_shares (
    id SERIAL PRIMARY KEY,
    document_id INTEGER REFERENCES documents(id),
    shared_with INTEGER REFERENCES users(id)
);

-- ---------------------------------------------------------------------------
-- IMPORTANT — VALIDATOR ACCOUNTS
--
-- The following user accounts are required for the automated validation
-- system used in the course. These accounts MUST always exist in the system.
--
-- The usernames and logical identities of these accounts must NOT be removed
-- or changed, as the validator depends on them to execute security tests.
--
-- The validator authenticates using the plaintext credentials defined below.
-- Therefore:
--
--  • These credentials must remain valid for authentication.
--  • The passwords themselves must not be changed.
--
-- You are free to improve the authentication system (e.g., password hashing,
-- stronger password policies, etc.). If you implement password hashing or
-- other changes to the login mechanism, ensure that the credentials below
-- still successfully authenticate.
--
-- In other words: the authentication implementation may change, but the
-- following username/password combinations must continue to work.
--
-- These accounts are used by the automated validator to test:
--   • authentication
--   • authorization
--   • document sharing
--   • access control
--   • administrative operations
--
-- Removing or altering these accounts will cause automated validation to fail.
-- ---------------------------------------------------------------------------
INSERT INTO users (username, password, is_disabled, is_admin) VALUES
('admin', 'scrypt:32768:8:1$3vpY6PRAW3pWv6Mp$55b8305266b30d78bced6cd0c9a9eaf702090dc516f6b6616b478308d8168e09916535ac01e39f51e44aba4075aea08bbe0b311438d972fad63dd4c5cd56a8fa', FALSE, TRUE),
('alice', 'scrypt:32768:8:1$5zSK1n480V8BXG7L$0943df45cf47d3e5c90831533c3086438ee5660251c94bfa47c6dee23a42c5ddf47b8cd556e903e84fa8bbf1c15fc53838254f0abeb04386c1539e3f60b9e09e', FALSE, FALSE),
('bob', 'scrypt:32768:8:1$gD26GI5yrPTpixQG$6862487450473b6afd0302135fe2e4863d3bd84a2dfaafdfbc273f2c5578ab76c60a0858a872d27b49cb9a33302b0ebeac1a04af11538bd37f10754c85d5978b', FALSE, FALSE);