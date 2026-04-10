<?php

namespace DBAuth\Console;

use DB;
use Exception;
use Backend\Models\User as BackendUser;
use DBAuth\PostGreSQLManager as DBManager;
use DBAuth\Models\Settings;
use Winter\Storm\Console\Command;

/**
 * DBAuth setup and verification console command.
 *
 * DBAuth uses TWO PostgreSQL roles per WinterCMS backend user:
 *
 *   1. Named role  — e.g. "admin"
 *      Used only for the initial login POST.  Must have CREATEROLE so it can
 *      update the token role's password during login.
 *
 *   2. Token role  — e.g. "token_<database>_<backend_users.id>"
 *      Used for every subsequent request (identified from the session cookie).
 *      Password is set to backend_users.persist_code on every successful login,
 *      so it rotates automatically.
 *
 * Cross-grant required:
 *   GRANT token_role TO named_role WITH ADMIN OPTION
 *   — allows the named role to ALTER the token role's password at login time.
 *
 * Setting required:
 *   DBAuth Settings → auto_create_db_user = 1
 *   — activates the backend.user.login listener that calls updateDBPassword().
 *
 * Artisan startup (Phase B / DB_USERNAME=<DBAUTH>):
 *   When .env has DB_USERNAME=<DBAUTH>, artisan cannot connect with the sentinel
 *   value. Set ARTISAN_AUTO_LOGIN=1 and ARTISAN_DEV_PASSWORD=<password> in .env
 *   and create an "artisan" PostgreSQL role with database access so that artisan
 *   commands (including this one) can run without interactive prompting.
 *   The "artisan" role name is hardcoded in ServiceProvider::showLoginScreen().
 *   The artisan role must NOT have SUPERUSER — it only needs database access.
 *
 * Frontend user (informational — not managed by this command):
 *   An unprivileged "frontend" role connects for all non-backend HTTP requests.
 *   It needs SELECT on most tables plus write access to session/log/cache tables:
 *     GRANT CONNECT ON DATABASE <db> TO frontend;
 *     GRANT USAGE ON SCHEMA public TO frontend;
 *     GRANT SELECT ON ALL TABLES IN SCHEMA public TO frontend;
 *     GRANT TRIGGER ON ALL TABLES IN SCHEMA public TO frontend;
 *     GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO frontend;
 *     GRANT INSERT, UPDATE, DELETE ON sessions, cache, system_event_logs,
 *           system_request_logs, cms_theme_logs, acorn_user_throttle TO frontend;
 *     GRANT UPDATE ON acorn_user_users TO frontend;
 *   Set DBAUTH_FRONTEND_USER=frontend and DBAUTH_FRONTEND_PASSWORD=<pwd> in .env.
 *
 * Usage examples:
 *   # Initial setup (Phase A — DB_USERNAME=createsystem superuser):
 *   php artisan dbauth:setup-access --login=admin --password=adminpass --enable-auto-create
 *
 *   # Include artisan role for Phase B server startup (auto-fix .env with --yes):
 *   php artisan dbauth:setup-access --login=admin --password=adminpass \
 *       --enable-auto-create --artisan-role --artisan-password=artisanpass --yes
 *
 *   # Verify an existing installation:
 *   php artisan dbauth:setup-access --check
 *
 *   # Set up / re-sync a specific user (equivalent to winter:passwd for DBAuth):
 *   php artisan dbauth:setup-access --login=john --password=newpass
 */
class SetupAccess extends Command
{
    /**
     * @var string The console command name.
     */
    protected static $defaultName = 'dbauth:setup-access';

    /**
     * @var string The name and signature of this command.
     */
    protected $signature = 'dbauth:setup-access
        {--login=admin        : WinterCMS backend_users login (also the PostgreSQL role name)}
        {--password=          : Password for the named PostgreSQL role}
        {--id=                : backend_users.id for the token role (auto-detected if omitted)}
        {--check              : Verify setup only — report issues and exit 1 if any found}
        {--yes                : Auto-fix all issues without confirmation (-y shorthand: use --yes)}
        {--enable-auto-create : Enable the auto_create_db_user DBAuth setting}
        {--artisan-role       : Create/verify the "artisan" role for ARTISAN_AUTO_LOGIN}
        {--artisan-password=  : Password for the artisan role (defaults to --password)}
    ';

    /**
     * @var string The console command description.
     */
    protected $description = 'Set up and verify PostgreSQL roles and grants for DBAuth authentication';

    /** @var bool Whether we are in check-only mode (no writes). */
    private bool $checkOnly;

    /** @var bool Whether to auto-fix without confirmation prompts. */
    private bool $autoFix;

    /** @var int Count of issues found during checks. */
    private int $issues = 0;

    /**
     * Execute the console command.
     * @return int Exit code — 0 = OK, 1 = issues found (check mode only)
     */
    public function handle(): int
    {
        $this->checkOnly = (bool) $this->option('check');
        $this->autoFix   = (bool) $this->option('yes');
        $login           = $this->option('login') ?: 'admin';
        $password        = $this->option('password');
        $idOption        = $this->option('id');

        $mode = $this->checkOnly ? '<comment>CHECK</comment>' : '<info>SETUP</info>';
        $this->line("DBAuth access $mode — login: <info>$login</info>");
        $this->line('');

        // ── Step 1: Verify DBAuth sentinel is active ──────────────────────────
        // DBAuth only intercepts logins when DB_USERNAME=<DBAUTH> in .env.
        // Phase A (DB_USERNAME=real user) shows the standard WinterCMS login page;
        // DBAuth still intercepts the pgsql connection on POST, so named roles must
        // exist even in Phase A.  Phase B (DB_USERNAME=<DBAUTH>) shows the custom
        // "Secure System" login page and fully activates DBAuth.
        $this->checkSentinel();

        // ── Step 2: Resolve backend_users.id ─────────────────────────────────
        // The token role name encodes the backend_users primary key:
        //   token_<database>_<id>   e.g. token_myapp_1
        // We look it up here so subsequent steps can construct the token name.
        $userId = $idOption ? (int) $idOption : $this->resolveUserId($login);

        // ── Step 3: Named PostgreSQL role ────────────────────────────────────
        // The named role (e.g. "admin") is used only for the initial login POST.
        // It must have:
        //   LOGIN        — to authenticate the POST
        //   CREATEROLE   — to ALTER the token role's password at login time
        // All table/sequence grants are needed because Winter runs queries as
        // this role during the brief window between login and session establishment.
        $this->checkNamedRole($login, $password);

        // ── Step 4: Token PostgreSQL role ─────────────────────────────────────
        // The token role (token_<db>_<id>) is used for every subsequent request.
        // Its password is set to backend_users.persist_code on each successful
        // login (via the backend.user.login listener when auto_create_db_user=1).
        // It needs LOGIN and the same table/sequence grants as the named role.
        // The cross-grant lets the named role ALTER the token role's password:
        //   GRANT token_role TO named_role WITH ADMIN OPTION
        if ($userId) {
            $database   = DBManager::configDatabase('database');
            $tokenLogin = "token_{$database}_{$userId}";
            $this->checkTokenRole($tokenLogin, $login);
        } else {
            $this->warn('  Skipping token role — no backend_users.id available.');
            $this->warn('  Run winter:up (migrations) then re-run without --id or provide --id=<n>.');
            $this->issues++;
        }

        // ── Step 5: DBAuth auto_create_db_user setting ────────────────────────
        // This setting enables the backend.user.login listener in ServiceProvider,
        // which calls PostGreSQLManager::updateDBPassword() to rotate the token
        // role's password to the new persist_code on every successful login.
        // Without this setting, logins succeed for the named role but fail on the
        // next request because the token role's password has not been updated.
        if ($this->option('enable-auto-create') || $this->checkOnly) {
            $this->checkAutoCreateSetting();
        }

        // ── Step 6: Artisan startup configuration ─────────────────────────────
        // When DB_USERNAME=<DBAUTH>, artisan cannot connect at startup using the
        // sentinel value. Two things are needed:
        //   a) ARTISAN_AUTO_LOGIN=1 and ARTISAN_DEV_PASSWORD in .env
        //      — checked and optionally fixed here (with --yes to skip confirmation)
        //   b) An "artisan" PostgreSQL role with database access
        //      — created/verified when --artisan-role is passed
        // The artisan role MUST NOT have SUPERUSER. In production environments it
        // is common for an existing artisan/admin role to be a superuser — this
        // command detects and removes that privilege.
        $artisanPassword = $this->option('artisan-password') ?: $password;
        $this->checkArtisanSetup($artisanPassword);

        // ── Summary ───────────────────────────────────────────────────────────
        $this->line('');
        if ($this->issues === 0) {
            $this->info('All checks passed.');
            return 0;
        }

        if ($this->checkOnly) {
            $this->error("{$this->issues} issue(s) found. Run without --check to fix them.");
            return 1;
        }

        $this->warn("{$this->issues} warning(s). Review output above.");
        return 0;
    }

    // =========================================================================
    // Check/setup methods
    // =========================================================================

    /**
     * Verify that the DBAuth sentinel (DB_USERNAME=<DBAUTH>) is active.
     * Warns if not — the named role must still exist even in Phase A.
     */
    private function checkSentinel(): void
    {
        $username = DBManager::configDatabase('username');
        $password = DBManager::configDatabase('password');

        if ($username === '<DBAUTH>' && $password === '<DBAUTH>') {
            $this->info('  [✓] DBAuth sentinel active (DB_USERNAME=<DBAUTH>)');
        } else {
            $this->warn("  [!] DBAuth sentinel NOT active — DB_USERNAME=$username");
            $this->line('      Phase B is not enabled; DBAuth still intercepts pgsql on POST.');
            $this->line('      Set DB_USERNAME=<DBAUTH> and DB_PASSWORD=<DBAUTH> in .env to activate.');
        }
    }

    /**
     * Look up backend_users.id for the given login.
     * Returns null if the user does not yet exist (migrations may not have run).
     */
    private function resolveUserId(string $login): ?int
    {
        try {
            $user = BackendUser::where('login', $login)->first();
            if ($user) {
                $this->info("  [✓] backend_users: login=$login id={$user->id}");
                return $user->id;
            }
            // User not found — either migrations haven't run or user doesn't exist yet.
            $this->warn("  [!] backend_users: no row with login=$login");
            $this->line('      Run winter:up then create the user via the backend or winter:passwd.');
            $this->issues++;
            return null;
        } catch (Exception $ex) {
            // Table may not exist if migrations haven't run.
            $this->warn('  [!] Cannot query backend_users: ' . $ex->getMessage());
            $this->issues++;
            return null;
        }
    }

    /**
     * Check or create the named PostgreSQL role (e.g. "admin").
     *
     * Required attributes:
     *   LOGIN      — so the initial login POST can authenticate
     *   CREATEROLE — so this role can ALTER the token role's password at login
     *
     * Required grants:
     *   CONNECT ON DATABASE, USAGE ON SCHEMA public,
     *   ALL ON ALL TABLES, ALL ON ALL SEQUENCES
     */
    private function checkNamedRole(string $login, ?string $password): void
    {
        $this->line('');
        $this->line("  Named role: <info>$login</info>");

        $attrs = DBManager::dbUserAttributes($login);

        if ($attrs === false) {
            // Role does not exist.
            if ($this->checkOnly) {
                $this->error("  [✗] PostgreSQL role \"$login\" does not exist.");
                $this->line('      Create with: CREATE ROLE ' . $login . ' WITH LOGIN CREATEROLE PASSWORD \'<pwd>\';');
                $this->issues++;
                return;
            }

            if (!$password) {
                $this->error("  [✗] Role \"$login\" missing and no --password supplied — cannot create.");
                $this->issues++;
                return;
            }

            $this->line("  Creating role \"$login\" with LOGIN CREATEROLE ...");
            DBManager::createDBUser($login, $password, false, true, ['all' => true]);
            $this->info("  [✓] Role \"$login\" created.");
            return;
        }

        // Role exists — check attributes.
        $this->reportAttr('LOGIN',      $attrs['LOGIN'],      $login, 'ALTER ROLE ' . $login . ' WITH LOGIN;');
        $this->reportAttr('CREATEROLE', $attrs['CREATEROLE'], $login, 'ALTER ROLE ' . $login . ' WITH CREATEROLE;');

        // Check database CONNECT privilege.
        $this->checkDatabaseGrant($login);

        // Check schema USAGE privilege.
        $this->checkSchemaGrant($login);

        // If not check-only and password supplied, update the password.
        if (!$this->checkOnly && $password) {
            DBManager::updateDBPassword($password, $login);
            $this->info("  [✓] Password updated for \"$login\".");
        }
    }

    /**
     * Check or create the token PostgreSQL role (e.g. "token_myapp_1").
     *
     * The token role:
     *   - Must have LOGIN so session-based requests can authenticate.
     *   - Password is rotated to backend_users.persist_code on every login
     *     (requires auto_create_db_user=1 and the cross-grant below).
     *
     * Cross-grant:
     *   GRANT token_role TO named_role WITH ADMIN OPTION
     *   Allows the named role to ALTER the token role's password during login.
     *   This is checked/created here after the token role exists.
     */
    private function checkTokenRole(string $tokenLogin, string $namedLogin): void
    {
        $this->line('');
        $this->line("  Token role: <info>$tokenLogin</info>");

        $attrs = DBManager::dbUserAttributes($tokenLogin);

        if ($attrs === false) {
            if ($this->checkOnly) {
                $this->error("  [✗] Token role \"$tokenLogin\" does not exist.");
                $this->line('      DBAuth creates this automatically when auto_create_db_user=1 and a user is saved.');
                $this->line('      Or create manually:');
                $this->line("        CREATE ROLE \"$tokenLogin\" WITH LOGIN PASSWORD '<random>';");
                $this->line("        GRANT \"$tokenLogin\" TO \"$namedLogin\" WITH ADMIN OPTION;");
                $this->issues++;
                return;
            }

            // Create the token role with a random initial password.
            // The password will be overwritten with persist_code on the next login.
            $initialPassword = $this->randomString(32);
            $this->line("  Creating token role \"$tokenLogin\" ...");
            DBManager::createDBUser(
                $tokenLogin,
                $initialPassword,
                false,   // not superuser
                false,   // no CREATEROLE needed for token role
                ['all' => true],
                [$namedLogin]  // GRANT token TO namedLogin WITH ADMIN OPTION
            );
            $this->info("  [✓] Token role \"$tokenLogin\" created.");

            // createDBUser already sets the cross-grant via $associateUsers, but we
            // verify / report it below for transparency.
        } else {
            $this->reportAttr('LOGIN', $attrs['LOGIN'], $tokenLogin, "ALTER ROLE \"$tokenLogin\" WITH LOGIN;");
            $this->checkDatabaseGrant($tokenLogin);
        }

        // ── Cross-grant: named_role can manage token_role ─────────────────────
        // Without this ADMIN OPTION, the named role cannot ALTER the token role's
        // password in updateDBPassword() → login succeeds but the next request
        // (which uses the token role) fails with password auth error.
        $this->checkAdminOption($namedLogin, $tokenLogin);
    }

    /**
     * Check or enable the auto_create_db_user DBAuth setting.
     *
     * This setting enables the backend.user.login listener that calls
     * PostGreSQLManager::updateDBPassword($persistCode, $tokenLoginName).
     * Without it, logins succeed as the named role but subsequent requests fail
     * because the token role's password has not been rotated.
     */
    private function checkAutoCreateSetting(): void
    {
        $this->line('');
        $current = Settings::get('auto_create_db_user');

        if ($current == '1') {
            $this->info('  [✓] DBAuth setting: auto_create_db_user = 1');
            return;
        }

        if ($this->checkOnly) {
            $this->error("  [✗] DBAuth setting auto_create_db_user is not enabled (current: \"$current\").");
            $this->line('      Enable via the backend (Settings → DBAuth) or re-run with --enable-auto-create.');
            $this->issues++;
            return;
        }

        Settings::set('auto_create_db_user', '1');
        $this->info('  [✓] DBAuth setting auto_create_db_user set to 1.');
    }

    /**
     * Check the artisan startup configuration:
     *   (a) ARTISAN_AUTO_LOGIN=1 and ARTISAN_DEV_PASSWORD in .env
     *   (b) The "artisan" PostgreSQL role exists and is NOT SUPERUSER
     *
     * (a) is always checked/fixed (required whenever DB_USERNAME=<DBAUTH>).
     * (b) is only created when --artisan-role is passed; existence and
     *     SUPERUSER status are always checked in --check mode.
     */
    private function checkArtisanSetup(?string $artisanPassword): void
    {
        $this->line('');
        $this->line('  Artisan startup configuration:');

        // ── (a) .env ARTISAN_AUTO_LOGIN ───────────────────────────────────────
        // When DB_USERNAME=<DBAUTH>, ServiceProvider::showLoginScreen() is called
        // at artisan startup. Without ARTISAN_AUTO_LOGIN=1, it prompts readline()
        // interactively — which hangs non-interactive CI or cron runs.
        // With ARTISAN_AUTO_LOGIN=1, it uses username "artisan" (hardcoded) and
        // ARTISAN_DEV_PASSWORD for the PostgreSQL connection.
        $this->checkEnvArtisanLogin($artisanPassword);

        // ── (b) "artisan" PostgreSQL role ─────────────────────────────────────
        $createRole  = (bool) $this->option('artisan-role');
        $attrs        = DBManager::dbUserAttributes('artisan');
        $roleExists   = ($attrs !== false);

        if (!$roleExists && !$createRole && !$this->checkOnly) {
            // Not asked to create; skip silently.
            return;
        }

        if (!$roleExists) {
            if ($this->checkOnly) {
                $this->error('  [✗] PostgreSQL role "artisan" does not exist.');
                $this->line('      Create with: CREATE ROLE artisan WITH LOGIN PASSWORD \'<pwd>\';');
                $this->line('      Then grant database access. Re-run with --artisan-role to automate.');
                $this->issues++;
                return;
            }

            if (!$createRole) return;

            if (!$artisanPassword) {
                $this->error('  [✗] Role "artisan" missing and no password supplied.');
                $this->line('      Use --artisan-password=<pwd> or --password=<pwd>.');
                $this->issues++;
                return;
            }

            // The artisan role only needs to connect and run basic queries.
            // Full grants prevent errors from Winter's startup DB test
            // (select 1 from winter_translate_messages limit 1).
            $this->line('  Creating role "artisan" with LOGIN and full grants ...');
            DBManager::createDBUser('artisan', $artisanPassword, false, false, ['all' => true]);
            $this->info('  [✓] Role "artisan" created.');
            return;
        }

        $this->info('  [✓] Role "artisan" exists.');

        // ── Security: artisan must NOT have SUPERUSER ─────────────────────────
        // SUPERUSER bypasses all PostgreSQL row-level security and access controls.
        // The artisan role is used for non-interactive server startup, not
        // privileged administration. If a production DBA created the artisan role
        // as a superuser, this must be corrected.
        if ($attrs['SUPERUSER']) {
            $this->warn('  [!] "artisan" role has SUPERUSER — this is a security risk.');
            $this->line('      The artisan role only needs database access, not SUPERUSER.');
            $this->line('      Fix: ALTER ROLE artisan WITH NOSUPERUSER;');

            if ($this->checkOnly) {
                $this->issues++;
            } elseif ($this->autoFix || $this->confirm('    Remove SUPERUSER from "artisan" role?')) {
                DBManager::clearSUPERUSER('artisan');
                $this->info('  [✓] NOSUPERUSER applied to "artisan" role.');
            }
        } else {
            $this->info('  [✓] "artisan" role is NOT SUPERUSER — correct.');
        }

        $this->checkDatabaseGrant('artisan');

        if (!$this->checkOnly && $artisanPassword) {
            DBManager::updateDBPassword($artisanPassword, 'artisan');
            $this->info('  [✓] Artisan role password updated.');
        }
    }

    /**
     * Check or fix ARTISAN_AUTO_LOGIN and ARTISAN_DEV_PASSWORD in .env.
     *
     * Reads and writes the application .env file directly.
     * Requires --yes to auto-write, or will prompt for confirmation.
     */
    private function checkEnvArtisanLogin(?string $artisanPassword): void
    {
        $autoLogin   = env('ARTISAN_AUTO_LOGIN');
        $devPassword = env('ARTISAN_DEV_PASSWORD', '');

        $loginOk    = ($autoLogin == '1');
        $passwordOk = !empty($devPassword);

        if ($loginOk && $passwordOk) {
            $this->info('  [✓] .env: ARTISAN_AUTO_LOGIN=1 and ARTISAN_DEV_PASSWORD are set.');
            return;
        }

        if (!$loginOk)    $this->warn('  [!] .env: ARTISAN_AUTO_LOGIN is not set to 1.');
        if (!$passwordOk) $this->warn('  [!] .env: ARTISAN_DEV_PASSWORD is not set.');

        if ($this->checkOnly) {
            $this->line('      Add to .env: ARTISAN_AUTO_LOGIN=1 and ARTISAN_DEV_PASSWORD=<artisan-password>');
            $this->issues++;
            return;
        }

        // Ask for confirmation before modifying .env (unless --yes was passed).
        if (!$this->autoFix && !$this->confirm('    Update .env with ARTISAN_AUTO_LOGIN / ARTISAN_DEV_PASSWORD?')) {
            $this->issues++;
            return;
        }

        $envPath = app()->environmentFilePath();
        $content = file_get_contents($envPath);
        $changed = false;

        // Set ARTISAN_AUTO_LOGIN=1.
        if (!$loginOk) {
            if (preg_match('/^ARTISAN_AUTO_LOGIN=/m', $content)) {
                $content = preg_replace('/^ARTISAN_AUTO_LOGIN=.*/m', 'ARTISAN_AUTO_LOGIN=1', $content);
            } else {
                $content .= "\nARTISAN_AUTO_LOGIN=1\n";
            }
            $this->info('  [✓] .env: ARTISAN_AUTO_LOGIN=1 set.');
            $changed = true;
        }

        // Set ARTISAN_DEV_PASSWORD (only if a password was supplied).
        if (!$passwordOk) {
            if ($artisanPassword) {
                if (preg_match('/^ARTISAN_DEV_PASSWORD=/m', $content)) {
                    $content = preg_replace(
                        '/^ARTISAN_DEV_PASSWORD=.*/m',
                        "ARTISAN_DEV_PASSWORD=$artisanPassword",
                        $content
                    );
                } else {
                    $content .= "ARTISAN_DEV_PASSWORD=$artisanPassword\n";
                }
                $this->info('  [✓] .env: ARTISAN_DEV_PASSWORD set.');
                $changed = true;
            } else {
                $this->warn('  [!] .env: ARTISAN_DEV_PASSWORD not set — no --artisan-password supplied.');
                $this->line('      Re-run with --artisan-password=<password> to set it automatically.');
                $this->issues++;
            }
        }

        if ($changed) {
            file_put_contents($envPath, $content);
        }
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Report a role attribute check (LOGIN, CREATEROLE, etc.).
     * Counts as an issue in check mode if the attribute is false.
     */
    private function reportAttr(string $attr, bool $value, string $login, string $fixHint): void
    {
        if ($value) {
            $this->info("  [✓] $login has $attr");
        } else {
            $this->error("  [✗] $login lacks $attr");
            $this->line("      Fix: $fixHint");
            $this->issues++;
        }
    }

    /**
     * Check whether a role has CONNECT privilege on the current database.
     * Uses pg_has_database_privilege() which works for any connected user.
     */
    private function checkDatabaseGrant(string $login): void
    {
        $database = DBManager::configDatabase('database');
        try {
            $loginQ = DBManager::escapeSQLValue($login);
            $dbQ    = DBManager::escapeSQLValue($database);
            $result = DB::selectOne("SELECT pg_has_database_privilege($loginQ, $dbQ, 'CONNECT') AS ok");
            if ($result && $result->ok) {
                $this->info("  [✓] $login has CONNECT on database \"$database\"");
            } else {
                $this->warn("  [!] $login may lack CONNECT on database \"$database\"");
                $this->line("      Fix: GRANT CONNECT ON DATABASE \"$database\" TO \"$login\";");
                if ($this->checkOnly) $this->issues++;
            }
        } catch (Exception $ex) {
            $this->warn("  [!] Could not check database grant for $login: " . $ex->getMessage());
        }
    }

    /**
     * Check whether a role has USAGE privilege on the public schema.
     */
    private function checkSchemaGrant(string $login): void
    {
        try {
            $loginQ = DBManager::escapeSQLValue($login);
            $result = DB::selectOne("SELECT has_schema_privilege($loginQ, 'public', 'USAGE') AS ok");
            if ($result && $result->ok) {
                $this->info("  [✓] $login has USAGE on schema public");
            } else {
                $this->warn("  [!] $login may lack USAGE on schema public");
                $this->line("      Fix: GRANT USAGE ON SCHEMA public TO \"$login\";");
                if ($this->checkOnly) $this->issues++;
            }
        } catch (Exception $ex) {
            $this->warn("  [!] Could not check schema grant for $login: " . $ex->getMessage());
        }
    }

    /**
     * Check or grant ADMIN OPTION from memberLogin on roleLogin.
     *
     * i.e. "GRANT roleLogin TO memberLogin WITH ADMIN OPTION"
     *
     * This is required so that memberLogin (the named role, e.g. "admin") can
     * ALTER the password of roleLogin (the token role, e.g. "token_myapp_1")
     * during login without needing SUPERUSER.
     */
    private function checkAdminOption(string $memberLogin, string $roleLogin): void
    {
        $memberQ = DBManager::escapeSQLValue($memberLogin);
        $roleQ   = DBManager::escapeSQLValue($roleLogin);

        try {
            $result = DB::selectOne("
                SELECT m.admin_option
                FROM pg_auth_members m
                JOIN pg_roles r  ON r.oid  = m.roleid
                JOIN pg_roles mr ON mr.oid = m.member
                WHERE r.rolname = $roleQ AND mr.rolname = $memberQ AND m.admin_option = TRUE
            ");

            if ($result) {
                $this->info("  [✓] GRANT \"$roleLogin\" TO \"$memberLogin\" WITH ADMIN OPTION");
                return;
            }
        } catch (Exception $ex) {
            $this->warn('  [!] Could not check admin_option: ' . $ex->getMessage());
        }

        if ($this->checkOnly) {
            $this->error("  [✗] \"$memberLogin\" lacks ADMIN OPTION on \"$roleLogin\".");
            $this->line("      Fix: GRANT \"$roleLogin\" TO \"$memberLogin\" WITH ADMIN OPTION;");
            $this->issues++;
            return;
        }

        // Grant ADMIN OPTION so the named role can update the token role's password.
        $memberN = DBManager::escapeSQLName($memberLogin);
        $roleN   = DBManager::escapeSQLName($roleLogin);
        DB::unprepared("GRANT $roleN TO $memberN WITH ADMIN OPTION;");
        $this->info("  [✓] Granted \"$roleLogin\" TO \"$memberLogin\" WITH ADMIN OPTION.");
    }

    /**
     * Generate a random string (used for initial token role password).
     */
    private function randomString(int $length = 32): string
    {
        return bin2hex(random_bytes($length / 2));
    }
}
