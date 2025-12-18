<?php namespace DBAuth;

use DB;
use Illuminate\Support\Facades\Config;
use BackendAuth;
use Exception;
use Backend\Models\User;
use function False\tRUE;

class PostGreSQLManager {
    public static function configDatabase(?string $key): array|string
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

    public static function dbUserExists(string|NULL $login): bool
    {
        // TODO: Prepare statement for DB::select
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
            'LOGIN'      => $results[0]->rolcanlogin,
            'SUPERUSER'  => $results[0]->rolsuper,
            'CREATEROLE' => $results[0]->rolcreaterole,
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

    public static function revokeAllPrivileges(string $login): bool
    {
        $database       = self::configDatabase('database');
        $databaseName   = self::escapeSQLName($database);
        $loginName      = self::escapeSQLName($login);
        $userExists     = self::dbUserExists($login);
        if ($userExists) {
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
        $database       = self::configDatabase('database');
        $databaseName   = self::escapeSQLName($database);
        $loginName      = self::escapeSQLName($login);
        $loginString    = self::escapeSQLName($login, "'");
        $userExists     = self::dbUserExists($login);
        if ($userExists) {
            self::revokeAllPrivileges($login);
            DB::unprepared("DROP USER if exists $loginName;");
        }
        return $userExists;
    }

    public static function updatePassword(string $password, string|NULL $login = NULL): bool
    {
        // NULL $login = CURRENT_USER
        $loginName      = (is_null($login) ? 'CURRENT_USER' : self::escapeSQLName($login));
        $passwordString = self::escapeSQLName($password, "'");

        $exists = ($login ? self::dbUserExists($login) : TRUE);
        if (!$exists)   throw new Exception("User $loginName does not exist");
        if (!$password) throw new Exception("$password is blank");

        $sql     = "ALTER USER $loginName WITH PASSWORD $passwordString;";
        DB::unprepared($sql);

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

    public static function createDBUser(string $login, string $password, bool $asSuperUser = FALSE, array|NULL $options = NULL, array|NULL $associateUsers = NULL): bool
    {
        $database       = self::configDatabase('database');
        $databaseName   = self::escapeSQLName($database);
        $loginName      = self::escapeSQLName($login);
        // Attributes
        $passwordString = ($password       ? 'PASSWORD ' . self::escapeSQLName($password, "'") : '');
        $attSuperuser   = ($asSuperUser    ? 'SUPERUSER'  : '');

        $sql            = "CREATE USER $loginName WITH LOGIN CREATEROLE $attSuperuser $passwordString;";
        DB::unprepared($sql);

        if ($associateUsers) {
            foreach ($associateUsers as $fromLogin) {
                // PostGreSQL requires CREATEROLE and ADMIN option to manage each other
                try {
                    DB::unprepared("GRANT $fromLogin TO $login WITH ADMIN OPTION;");
                } catch (Exception $ex) {
                    // ADMIN option is likely to already be granted
                }
            }
        }

        // $options come from the DatabaseAuthorisation <form>
        // TODO: This is too much access! Let's reduce it
        // Maybe use a clone user
        $withgrant = ''; // WITH GRANT OPTION
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

        return TRUE;
    }
}