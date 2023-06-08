<?php namespace DBAuth;

use DB;
use Illuminate\Support\Facades\Config;

class PostGreSQLManager {
    public static function configDatabase(?string $key): array|string
    {
        $conn   = Config::get('database.default');
        $config = Config::get("database.connections.$conn");
        return ($key ? $config[$key] : $config);
    }

    public static function escapeSQLName(string $name, ?string $quote = '"'): string
    {
        $name  = preg_replace("/(['\"])/", '\\\$1', $name);
        return "$quote$name$quote"; 
    }

    public static function userExists(string $login): bool
    {
        $loginString = self::escapeSQLName($login, "'");
        return (bool) DB::select("SELECT 1 FROM pg_roles WHERE rolname=$loginString;");
    }

    public static function checkDropDBUser(string $login): bool
    {
        // Delete Completely
        $databaseName   = self::escapeSQLName(self::configDatabase('database'));
        $loginName      = self::escapeSQLName($login);
        $loginString    = self::escapeSQLName($login, "'");
        $userExists     = self::userExists($login);
        if ($userExists) {
            DB::unprepared("REVOKE ALL ON ALL TABLES IN schema public from $loginName;");
            DB::unprepared("REVOKE ALL ON ALL SEQUENCES IN schema public from $loginName;");
            DB::unprepared("REVOKE ALL ON ALL FUNCTIONS IN schema public from $loginName;");
            DB::unprepared("REVOKE ALL ON schema public from $loginName;");
            DB::unprepared("REVOKE ALL ON database $databaseName from $loginName;");
            DB::unprepared("REASSIGN OWNED BY $loginName TO postgres;");
            DB::unprepared("DROP USER if exists $loginName;");
        }
        return $userExists;
    }

    public static function checkCreateDBUser(string $login, string $password, ?bool $withCreateRole = FALSE, ?bool $asSuperUser = FALSE, ?bool $withGrantOption = FALSE): bool
    {
        $created  = FALSE;
        $databaseName   = self::escapeSQLName(self::configDatabase('database'));
        $loginName      = self::escapeSQLName($login);
        $passwordString = self::escapeSQLName($password, "'");
        $loginString    = self::escapeSQLName($login,    "'");

        // Check for existence (PostGreSQL specific)
        if (self::userExists($login)) {
            // Update the password
            DB::unprepared("ALTER ROLE $loginName WITH PASSWORD $passwordString;");
        } else {
            // Create
            // TODO: Make RLS / table access configurable
            try {
                $createrole = ($withCreateRole  ? 'CREATEROLE'        : '');
                $superuser  = ($asSuperUser     ? 'SUPERUSER'         : '');
                $withgrant  = ($withGrantOption ? 'WITH GRANT OPTION' : '');
                DB::unprepared("CREATE USER $loginName with $createrole $superuser password $passwordString;");
                // TODO: This is too much access! Let's reduce it
                DB::unprepared("GRANT ALL ON DATABASE $databaseName TO $loginName $withgrant;");
                DB::unprepared("GRANT ALL ON SCHEMA public TO $loginName $withgrant;");
                DB::unprepared("GRANT ALL PRIVILEGES ON ALL TABLES    IN SCHEMA public TO $loginName $withgrant;");
                DB::unprepared("GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO $loginName $withgrant;");
                DB::unprepared("GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO $loginName $withgrant;");
                $created = TRUE;
            } catch (QueryException $ex) {
                self::showLoginScreen($ex);
            }
        }

        return $created;
    }
}