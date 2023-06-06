<?php namespace AcornAssociated\Auth\Classes;

use DB as IlluminateDB;

class DB
{
    public static function createUser(string $login, string $password)
    {
        $database = 'winter'; // TODO: Get database name!
        $sql   = "DROP USER if exists \"$login\";";
        $sql  .= "CREATE USER \"$login\" with password '$password';";
        $sql  .= "GRANT USAGE ON DATABSE \"$database\" TO \"$login\";";
        $sql  .= "GRANT USAGE ON SCHEMA public TO \"$login\";";
        $sql  .= "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO \"$login\";";
        DB::unprepared($sql);
    }
}