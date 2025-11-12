<?php namespace DBAuth;

use DB;
use Illuminate\Support\Facades\Config;
use BackendAuth;
use Exception;
use Backend\Models\User;

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

    public static function dbUserName(User $user = NULL): string
    {
        if (is_null($user)) $user = BackendAuth::user();
        return "token_$user->id";
    }
    
    public static function escapeSQLName(string $name, ?string $quote = '"'): string
    {
        $name  = preg_replace("/(['\"])/", '\\\$1', $name);
        return "$quote$name$quote"; 
    }

    public static function userExists(string $login): bool
    {
        // TODO: Prepare statement for DB::select
        $loginString = self::escapeSQLName($login, "'");
        return (bool) DB::select("SELECT 1 FROM pg_roles WHERE rolname=$loginString;");
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
        $userExists     = self::userExists($login);
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
        $userExists     = self::userExists($login);
        if ($userExists) {
            self::revokeAllPrivileges($login);
            DB::unprepared("DROP USER if exists $loginName;");
        }
        return $userExists;
    }

    public static function upCreateDBUser(string $login, string|NULL $password = NULL, ?bool $withCreateRole = FALSE, ?bool $asSuperUser = FALSE, ?bool $withGrantOption = FALSE, ?array $options = array()): bool
    {
        // Update or Create the DB user
        $database       = self::configDatabase('database');
        $databaseName   = self::escapeSQLName($database);
        $loginName      = self::escapeSQLName($login);
        // Attributes
        $passwordString = ($password       ? 'PASSWORD ' . self::escapeSQLName($password, "'") : '');
        $attCreaterole  = ($withCreateRole ? 'CREATEROLE' : '');
        $attSuperuser   = ($asSuperUser    ? 'SUPERUSER'  : '');
        $attLogin       = 'LOGIN';

        $exists  = self::userExists($login);
        $command = ($exists ? 'ALTER' : 'CREATE'); 
        if (!$exists && !$password) throw new Exception("Cannot create user $loginName without a DB password");
        DB::unprepared("$command USER $loginName WITH $attCreaterole $attSuperuser $attLogin $passwordString;");

        // $options come from the DatabaseAuthorisation <form>
        // TODO: This is too much access! Let's reduce it
        // Maybe use a clone user
        $withgrant = ($withGrantOption ? 'WITH GRANT OPTION' : '');
        if (self::hasOption($options, 'grant_database_usage') && $database) 
            DB::unprepared("GRANT ALL ON DATABASE $databaseName TO $loginName $withgrant;");
        if (self::hasOption($options, 'grant_schema_usage')) 
            DB::unprepared("GRANT ALL ON SCHEMA public TO $loginName $withgrant;");
        if (self::hasOption($options, 'grant_tables_all')) 
            DB::unprepared("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO $loginName $withgrant;");
        if (self::hasOption($options, 'grant_sequences_all')) 
            DB::unprepared("GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO $loginName $withgrant;");
        if (self::hasOption($options, 'grant_functions_all')) 
            DB::unprepared("GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO $loginName $withgrant;");

        return !$exists;
    }
}