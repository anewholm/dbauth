# DBAuth — Database-credential login for WinterCMS

[![CI](https://github.com/anewholm/dbauth/actions/workflows/ci.yml/badge.svg)](https://github.com/anewholm/dbauth/actions/workflows/ci.yml)
[![CodeQL](https://github.com/anewholm/dbauth/actions/workflows/codeql.yml/badge.svg)](https://github.com/anewholm/dbauth/actions/workflows/codeql.yml)

DBAuth is a WinterCMS module that logs directly into PostgreSQL using the end-user's credentials. No database username or password is stored in `.env` or `config/database.php`. Each authenticated session is backed by a dedicated, short-lived PostgreSQL role, enabling [Row Level Security (RLS)](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) policies to scope data access per user at the database level.

![Login Screen](login.png "DBAuth custom login screen")

## What it does

1. Serves a static HTML login page before any database connection is attempted.
2. On successful login, creates a session-scoped PostgreSQL role with the same privileges as the authenticated user.
3. All subsequent Laravel database connections for that session use the session role.
4. On logout, the session role is revoked immediately.
5. When a WinterCMS admin creates a new backend user, DBAuth provisions a matching PostgreSQL role automatically.

![DBAuth account setup](setup.png "Per-account DBAuth configuration")

## Why PostgreSQL only?

DBAuth is fundamentally built on PostgreSQL's `CREATEROLE`, `GRANT`, and Row Level Security features. MySQL has no equivalent. This is a deliberate architectural choice — the PostgreSQL security model is central to DBAuth's guarantees, not an incidental dependency.

**Requires PostgreSQL 12+. MySQL is not supported by design.**

## Compatibility

| WinterCMS | Laravel | PHP  | PostgreSQL |
|-----------|---------|------|------------|
| 1.2.0     | 9       | 8.1+ | 12+        |
| 1.2.x     | 10      | 8.1+ | 12+        |
| 1.2.x     | 11      | 8.2+ | 12+        |

## Prerequisites

- WinterCMS 1.2+ installed
- [Acorn module](https://github.com/anewholm/acorn) installed as `modules/acorn`
- PostgreSQL 12+ with a superuser account (needed during installation to create roles)

## Installation

1. Clone this repository into `modules/dbauth` inside your WinterCMS root:
   ```bash
   git clone https://github.com/anewholm/dbauth modules/dbauth
   ```

2. Clone the Acorn dependency into `modules/acorn`:
   ```bash
   git clone https://github.com/anewholm/acorn modules/acorn
   ```

3. Add both modules to `config/cms.php`:
   ```php
   'loadModules' => ['System', 'Backend', 'Cms', 'Acorn', 'DBAuth'],
   ```

4. Configure `.env` with your PostgreSQL superuser credentials and run migrations:
   ```
   DB_CONNECTION=pgsql
   DB_USERNAME=your_superuser
   DB_PASSWORD=your_password
   ```
   ```bash
   php artisan winter:up
   ```

5. Switch `.env` to DBAuth mode — replace the credentials with the sentinel values:
   ```
   DB_USERNAME=<DBAUTH>
   DB_PASSWORD=<DBAUTH>
   ```

6. Navigate to `/backend/auth` — the DBAuth login screen will appear.

## Custom login page

DBAuth serves its own static HTML login page to ensure no database connection is attempted before authentication. To customise it, create `public/resources/login.html`.

## Artisan

Artisan connects to the database during bootstrap. When `DB_USERNAME=<DBAUTH>`, DBAuth falls back to a standard development login. If that fails, it prompts interactively. This is intentional and safe for development use.

## Known limitations

- PostgreSQL only — no MySQL support.
- WinterCMS backend usernames cannot be changed after creation (WinterCMS limitation).
- Concurrent logins by the same user each receive their own session role; orphaned roles from crashed sessions are cleaned up on the next successful login.

## License

MIT
