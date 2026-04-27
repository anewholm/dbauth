<?php namespace DBAuth;

use DB;
use Illuminate\Support\Facades\Config;
use Exception;
use Illuminate\Database\Connectors\ConnectionFactory;
use DBAuth\Models\Settings;

class PostGreSQLManager {
    public static function configDatabase(string|NULL $key = NULL): array|string
    {
        $conn   = Config::get('database.default');
        $config = Config::get("database.connections.$conn");
        return ($key ? $config[$key] : $config);
    }

    public static function dbCURRENT_USER(): string
    {
        $results = DB::select('select CURRENT_USER;');
        return $results[0]->current_user;
    }

    public static function escapeSQLName(string $name, ?string $quote = '"'): string
    {
        $name  = preg_replace("/(['\"])/", '\\\$1', $name);
        return "$quote$name$quote"; 
    }

    public static function escapeSQLValue(string $name, ?string $quote = "'"): string
    {
        return self::escapeSQLName($name, $quote); 
    }

    public static function dbUserExists(string|NULL $login): bool
    {
        $loginString = self::escapeSQLName($login, "'");
        return (bool) ($login 
            ? DB::select("SELECT 1 FROM pg_roles WHERE rolname=$loginString;")
            : TRUE
        );
    }

    public static function dbUserAttributes(string $login): array|bool
    {
        // Allow exceptions to bubble normally
        // Return of FALSE indicates that the user does not exist
        // rolsuper | rolinherit | rolcreaterole | rolcreatedb | rolcanlogin | rolreplication
        $userOptions = FALSE;
        $loginString = self::escapeSQLName($login, "'");
        $results     = DB::select("select * from pg_roles where rolname=$loginString;");
        $userResult  = (isset($results[0]) ? $results[0] : NULL);
        if ($userResult) $userOptions = array(
            'LOGIN'      => $userResult->rolcanlogin,
            'SUPERUSER'  => $userResult->rolsuper,
            'CREATEROLE' => $userResult->rolcreaterole,
        );
        return $userOptions;
    }

    public static function hasOption(array $options, string $name, $default = NULL)
    {
        if (substr($name, 0, 16) != 'acorn_')
            $name = "acorn_$name";
        $name     = "_$name";
        $all      = (isset($options['all']) && $options['all']);
        $specific = (isset($options[$name]) && $options[$name]);

        return ($all || $specific);
    }

    public static function revokeAllDBPrivileges(string $login): bool
    {
        /*
        REVOKE ALL ON ALL FUNCTIONS IN schema public from "token_8_no" CASCADE;
        REVOKE ALL ON ALL SEQUENCES IN schema public from "token_8_no" CASCADE;
        REVOKE ALL ON ALL TABLES IN schema public from "token_8_no" CASCADE;
        REVOKE ALL ON schema public from "token_8_no" CASCADE;
        REVOKE ALL ON database "justice" from "token_8_no" CASCADE;
        REASSIGN OWNED BY "token_8_no" TO postgres;
        drop user "token_8_no"
        */
        $database       = self::configDatabase('database');
        $databaseName   = self::escapeSQLName($database);
        $loginName      = self::escapeSQLName($login);
        $userExists     = self::dbUserExists($login);
        if ($userExists) {
            $templateRole = Settings::get('template_role');
            if ($templateRole) {
                $templateRoleN = self::escapeSQLName($templateRole);
                try { DB::unprepared("REVOKE $templateRoleN FROM $loginName;"); } catch (Exception $e) {}
            }
            DB::unprepared("REVOKE ALL ON ALL FUNCTIONS IN schema public from $loginName CASCADE;");
            DB::unprepared("REVOKE ALL ON ALL SEQUENCES IN schema public from $loginName CASCADE;");
            DB::unprepared("REVOKE ALL ON ALL TABLES IN schema public from $loginName CASCADE;");
            DB::unprepared("REVOKE ALL ON schema public from $loginName CASCADE;");
            if ($database) DB::unprepared("REVOKE ALL ON database $databaseName from $loginName CASCADE;");
            DB::unprepared("REASSIGN OWNED BY $loginName TO postgres;");
        }
        return $userExists;
    }

    public static function checkDropDBUser(string $login): bool
    {
        // Delete DB User Completely
        $loginName      = self::escapeSQLName($login);
        $userExists     = self::dbUserExists($login);
        if ($userExists) {
            self::revokeAllDBPrivileges($login);
            DB::unprepared("DROP USER if exists $loginName;");
        }
        return $userExists;
    }

    public static function updateDBPassword(string $password, string|NULL $login = NULL, string|NULL $oldPassword = NULL): bool
    {
        // NULL $login = CURRENT_USER
        $loginName      = (is_null($login) ? 'CURRENT_USER' : self::escapeSQLName($login));
        $passwordString = self::escapeSQLName($password, "'");

        $exists = ($login ? self::dbUserExists($login) : TRUE);
        if (!$exists)   throw new Exception("User $loginName does not exist");
        if (!$password) throw new Exception("$password is blank");

        if ($oldPassword) {
            // Connect as the target user
            $config = self::configDatabase();
            $config['username'] = $login;
            $config['password'] = $oldPassword;
            $connFactory = new ConnectionFactory(app());
            $db2 = $connFactory->make($config);

            // Run the CURRENT_USER update
            $sql = "ALTER USER CURRENT_USER WITH PASSWORD $passwordString;";
            $db2->unprepared($sql);
            $db2->disconnect();
        } else {
            $sql = "ALTER USER $loginName WITH PASSWORD $passwordString;";
            DB::unprepared($sql);
        }

        return TRUE;
    }

    public static function makeSUPERUSER(string|NULL $login = NULL): bool
    {
        // NULL $login = CURRENT_USER
        $loginName = (is_null($login) ? 'CURRENT_USER' : self::escapeSQLName($login));
        $sql       = "ALTER USER $loginName WITH SUPERUSER;";
        DB::unprepared($sql);
        return TRUE;
    }
    
    public static function clearSUPERUSER(string|NULL $login = NULL): bool
    {
        // NULL $login = CURRENT_USER
        $loginName = (is_null($login) ? 'CURRENT_USER' : self::escapeSQLName($login));
        $sql       = "ALTER USER $loginName WITH NOSUPERUSER;";
        DB::unprepared($sql);
        return TRUE;
    }

    /**
     * Create a non-login template role with the standard WinterCMS grant set.
     *
     * The role is created with NOLOGIN (session users inherit grants via GRANT role TO user).
     * Grants cover all existing tables/sequences/functions in the public schema, plus
     * ALTER DEFAULT PRIVILEGES so future plugin migrations get the same access automatically.
     * No custom GRANTs are needed from the developer for plugins that use the public schema.
     */
    public static function createTemplateRole(string $roleName, string $database): void
    {
        $roleN = self::escapeSQLName($roleName);
        $dbN   = self::escapeSQLName($database);
        try { DB::unprepared("CREATE ROLE $roleN NOLOGIN;"); } catch (Exception $e) {}
        DB::unprepared("GRANT CONNECT ON DATABASE $dbN TO $roleN;");
        DB::unprepared("GRANT USAGE ON SCHEMA public TO $roleN;");
        DB::unprepared("GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO $roleN;");
        DB::unprepared("GRANT USAGE,UPDATE ON ALL SEQUENCES IN SCHEMA public TO $roleN;");
        DB::unprepared("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO $roleN;");
        // Future tables/sequences/functions created by plugin migrations also get grants
        DB::unprepared("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO $roleN;");
        DB::unprepared("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE,UPDATE ON SEQUENCES TO $roleN;");
        DB::unprepared("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO $roleN;");
    }

    /**
     * Grant a non-login template role to a session login user so it inherits all grants.
     * Hard-fails (Exception) if the template role does not exist — run dbauth:setup-access
     * --template-role=<name> to create it before creating session users.
     */
    public static function grantTemplateRole(string $login, string $roleName): void
    {
        $roleN  = self::escapeSQLName($roleName);
        $loginN = self::escapeSQLName($login);
        DB::unprepared("GRANT $roleN TO $loginN;");
    }

    public static function createDBUser(string $login, string $password, bool $asSuperUser = FALSE, bool $withCreateRole = FALSE, array|NULL $options = NULL, array|NULL $associateUsers = NULL): bool
    {
        $database       = self::configDatabase('database');
        $databaseName   = self::escapeSQLName($database);
        $loginName      = self::escapeSQLName($login);
        // Attributes
        $passwordName   = self::escapeSQLValue($password);
        $passwordAtt    = ($password       ? "PASSWORD $passwordName"  : '');
        $attSuperuser   = ($asSuperUser    ? 'SUPERUSER'   : '');
        $attCreateRole  = ($withCreateRole ? 'CREATEROLE'  : '');

        $sql            = "CREATE USER $loginName WITH LOGIN $attCreateRole $attSuperuser $passwordAtt;";
        DB::unprepared($sql);

        if ($associateUsers) {
            foreach ($associateUsers as $fromLogin) {
                // PostGreSQL requires CREATEROLE and ADMIN option to manage each other
                // This is used so that:
                //   the normal user can update the token_% user password 
                //   to the new persist_code during login
                $fromLoginName = self::escapeSQLName($fromLogin);
                try {
                    DB::unprepared("GRANT $loginName TO $fromLoginName WITH ADMIN OPTION;");
                } catch (Exception $ex) {
                    // ADMIN option is likely to already be granted
                }
            }
        }

        $templateRole = Settings::get('template_role');
        if ($templateRole) {
            // Inherit all grants from the template role. Hard-fails if the role was deleted —
            // the admin must re-run dbauth:setup-access --template-role=<name> to recreate it.
            self::grantTemplateRole($login, $templateRole);
        } else {
            // Legacy fallback for installs that have not configured a template role.
            if (self::hasOption($options, 'grant_database_usage') && $database)
                DB::unprepared("GRANT ALL ON DATABASE $databaseName TO $loginName;");
            if (self::hasOption($options, 'grant_schema_usage'))
                DB::unprepared("GRANT ALL ON SCHEMA public TO $loginName;");
            if (self::hasOption($options, 'grant_tables_all'))
                DB::unprepared("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO $loginName;");
            if (self::hasOption($options, 'grant_sequences_all'))
                DB::unprepared("GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO $loginName;");
            if (self::hasOption($options, 'grant_functions_all'))
                DB::unprepared("GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO $loginName;");
        }

        return TRUE;
    }
}