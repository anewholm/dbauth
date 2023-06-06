<?php namespace DBAuth;

use BackendAuth;
use Event;
use DB;

use System\Classes\SettingsManager;
use Winter\Storm\Support\ModuleServiceProvider;
use Illuminate\Database\Connectors\ConnectionFactory;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Facades\Config;
use Form as FormHelper;
use Backend\Models\User;
use Illuminate\Database\QueryException;
use PDOException;
//use Doctrine\DBAL\Driver\PDO\Exception;

class ServiceProvider extends ModuleServiceProvider
{
    use \System\Traits\SecurityController;
    
    public function boot()
    {
        if (self::isEnabled()) {
            // Note: we could have also used a DB extension:
            // app('db')->extend('pgsql', function($config, $name){return ServiceProvider::connectionFactory($config, $name);});
            Event::listen('backend.user.login', function($user)         {return ServiceProvider::backedUserLogin($user);});
            $username = self::morphConfig();
            if ($username === FALSE) {
                // Neither a login, nor a token
                self::showLoginScreen();
            }

            // Immediately test the database connection
            // with the new parameters
            // and the existence of the backend_users record
            // Note that the authorisation procedure has not happend yet
            try {
                $user = User::where('login', '=', $username)->get();
            } 
            catch (QueryException $ex) {
                self::showLoginScreen($ex);
            }
            if (is_null($user)) {
                // Database connection was successful
                // but backend_users record not there
                // JIT for login procedure
                $user = new User([
                    'login'      => $username,
                    'first_name' => $username,
                    'email'      => "$username@nowhere.com",
                    'password'   => $password,
                    'password_confirmation' => $password,
                ]);
                $user->save();
            }
        }
    }

    public function register()
    {
        SettingsManager::instance()->registerCallback(function ($manager) {
            $manager->registerSettingItems('Winter.Backend', [
                'dbauth' => [
                    'label'       => 'DataBase Authorisation settings',
                    'description' => 'Manage direct database authorisation setup.',
                    'category'    => 'system::lang.system.categories.system',
                    'icon'        => 'icon-cog',
                    'class'       => 'DBAuth\Models\Settings',
                    'order'       => 500,
                    'keywords'    => 'security database',
                    'permissions' => []
                ]
            ]);
        });
    }

    protected static function isEnabled()
    {
        // config/database.php username=<DYNAMIC> necessary for this functionality 
        $conn     = Config::get('database.default');
        $username = Config::get("database.connections.$conn.username");
        return $username == '<DYNAMIC>';
    }

    public static function backedUserLogin(User $user)
    {
        // Login to database has been successful
        // A token has been generated for future connections
        // Create a new user for the login token
        // as we already have a DB connection that can create users
        // It is important that the main login has GRANT OPTION and CREATE ROLES
        self::createUser("token_" . (int) $user->id, $user->getPersistCode());
    }

    public static function morphConfig()
    {
        $username    = FALSE;
        $input       = post();
        $conn        = Config::get('database.default');
        $databaseKey = "database.connections.$conn";
        $userKey     = "$databaseKey.username";
        $passKey     = "$databaseKey.password";
        $isLoggingIn = (isset($input['login']) && isset($input['password']));
        if ($isLoggingIn) {
            // Allow normal logging in process
            // The backend.user.login event below will create a DB user
            // for the resultant new login token
            $username = $input['login'];
            Config::set($userKey, $username);
            Config::set($passKey, $input['password']);
        } else {
            // Get the users id and auth token
            // from their browser client
            $authArray = Session::get('admin_auth');
            if (!$authArray) {
                $cookieArray = Cookie::get('admin_auth');
                $authArray   = @json_decode($cookieArray, true);
            }
            $hasAuthToken = (is_array($authArray) && count($authArray) == 2);

            if ($hasAuthToken) {
                // Note that a user with this token information
                // will have been created at the point of token creation
                //   Auth\Manager::setPersistCodeInSession()
                // using the Users actual original login credentials
                // to create the temporary user
                [$id, $token] = $authArray;
                $username = "token_$id";
                Config::set($userKey, $username);
                Config::set($passKey, $token);
            }
        }

        return $username;
    }

    public static function showLoginScreen(?PDOException $ex = NULL)
    {
        // XSRF protection
        //$cookie = $this->makeXsrfCookie();
        //setcookie($cookie->getName(), $cookie->getValue());
        //dump($cookie);
        //dump(Config::get('session'));
        //$html = str_replace('[SESSION_KEY]', FormHelper::getSessionKey(), $html);
        //$html = str_replace('[TOKEN]', Session::token(), $html);

        // Show the fixed HTML login screen and exit
        // to avoid any db access attempts from other plugins
        include self::loginScreenPath();

        // Prevent any further execution
        // as it may well try to connect to the database
        // and we have no credentials to do so
        exit(0);
    }

    protected static function createUser(string $login, string $password)
    {
        //$database = 'winter'; // TODO: Get database name!
        $login    = str_replace("'", "\\'", $login);
        $password = str_replace("'", "\\'", $password);
        $sql   = "DROP USER if exists \"$login\";";
        $sql  .= "CREATE USER \"$login\" with password '$password';";
        //$sql  .= "GRANT USAGE ON DATABSE \"$database\" TO \"$login\";";
        $sql  .= "GRANT USAGE ON SCHEMA public TO \"$login\";";
        $sql  .= "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO \"$login\";";
        DB::unprepared($sql);
    }

    protected static function loginScreenPath()
    {
        // TODO: publish this resource to app
        $dir     = dirname(__FILE__);
        $docroot = app()->basePath();
        $path    = "$docroot/public/resources/login.php";
        if (!file_exists($path)) $path = "$dir/resources/login.php";
        return $path;
    }
}