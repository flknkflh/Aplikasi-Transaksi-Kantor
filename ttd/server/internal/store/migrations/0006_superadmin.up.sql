-- Account management: a single bootstrapped super admin owns admin creation.
-- No column change (role is already a free-text column); this only enforces
-- "there is at most one superadmin" at the database level. The row itself is
-- created by the API on first boot from PQC_SUPERADMIN_USERNAME/PASSWORD.
CREATE UNIQUE INDEX IF NOT EXISTS accounts_one_superadmin
    ON accounts ((role)) WHERE role = 'superadmin';
