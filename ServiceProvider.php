<?php namespace DBAuth;

use Illuminate\Support\Facades\App;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Session\SessionManager;
use BackendAuth;
use Event;
use DB;
use Flash;
use Backend\Controllers\Users;
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
            // TODO: SECURITY: Disabled this because I cannot get XSRF to work
            // on the login form
            Config::set('cms.enableCsrfProtection', false);
            Session::start();

            // Check / Create a mirror token_$id database user 
            // upon successful login with main user credentials 
            Event::listen('backend.user.login', function($user) {
                return ServiceProvider::backedUserLogin($user);
            });

            // Trap Session / Cookie admin_auth on subsequent requests
            // to login with the token_$id user
            app('db')->extend('pgsql', function($config, $name){
                $username = ServiceProvider::morphConfig($config);
                // If neither a login, nor a token
                // then username will === FALSE, config is still <DBAUTH>
                // so we cannot connect to the database
                if ($username === FALSE) ServiceProvider::showLoginScreen();

                // Connect with the Config::* morphed credentials
                $connFactory = new ConnectionFactory(app());
                return $connFactory->make($config, $name);
            });

            // TODO: Post-DB-connect checkCreateBackendUser() 
            // BEFORE login
            // only for the main user

            // Immediately test the connection
            // Note that the authorisation procedure has not happend yet
            // and we cannot get the username / id yet from session
            DB::unprepared("select 1");
        }
    }

    public static function checkCreateBackendUser(string $username, string $password): User
    {
        try {
            $user = User::where('login', '=', $username)->get();
        } 
        catch (QueryException $ex) {
            ServiceProvider::showLoginScreen($ex);
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

        return $user;
    }

    protected static function isEnabled(): bool
    {
        // config/database.php username=<DBAUTH> necessary for this functionality 
        return self::configDatabase('username') == '<DBAUTH>';
    }

    public static function backedUserLogin(User $user): bool
    {
        // Login to database has been successful
        // A token has been generated for future connections
        // Create a new user for the login token
        // as we already have a DB connection that can create users
        // It is important that the main login has GRANT OPTION and CREATE ROLES
        return ServiceProvider::checkCreateTokenDBUser("token_" . (int) $user->id, $user->getPersistCode());
    }

    public static function morphConfig(array &$config): string|bool
    {
        // Note $config passed by reference
        // Return value of FALSE indicates no changes to config
        // so username may still == <DBAUTH>
        // causing connection failure
        $username    = FALSE;
        $input       = post();

        $isLoggingIn = (isset($input['login']) && isset($input['password']));
        if ($isLoggingIn) {
            // Allow normal logging in process
            // The backend.user.login event will create a DB user
            // for the resultant new login token
            $username = $input['login'];
            $config['username'] = $username;
            $config['password'] = $input['password'];
        } else {
            // Get the users id and auth token
            // from their browser client session / cookie
            // Laravel cookies are encrypted:
            //   EncryptCookies::decrypt(Request)
            //   Encrypter uses openssl_decrypt()
            //   helpers.php declares the generalised decrypt():
            //     app('encrypter')->decrypt($value, $unserialize);
            // Laravel decrypts the Session::* AFTER DB connection
            // so we have to do it manually here
            $authArray = Session::get('admin_auth');
            if (!$authArray) {
                if ($cookieArray = Cookie::get('admin_auth')) {
                    $authArray   = @json_decode($cookieArray, true);
                    if (!$authArray) {
                        $cookieArrayD = @decrypt($cookieArray, FALSE);
                        if ($cookieArrayD) {
                            $cookieArrayDA = explode('|', $cookieArrayD);
                            if (isset($cookieArrayDA[1])) {
                                $authArray = @json_decode($cookieArrayDA[1], true);
                            }
                        }
                    }
                }
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
                $config['username'] = $username;
                $config['password'] = $token;
            }
        }

        return $username;
    }

    public static function showLoginScreen(?PDOException $ex = NULL)
    {
        // TODO: SECURITY: XSRF protection is disabled above
        Session::start(); // => loadSession() && regenerateToken();
        //$cookie = $this->makeXsrfCookie();
        //setcookie($cookie->getName(), $cookie->getValue());
        $xsrf = Session::token();
        Session::save();
        //$sessionId = Session::getId();

        // Show the fixed HTML login screen and exit
        // to avoid any db access attempts from other plugins
        include ServiceProvider::loginScreenPath();

        // Prevent any further execution
        // as it may well try to connect to the database
        // and we have no credentials to do so
        exit(0);
    }

    protected static function configDatabase(?string $key): array|string
    {
        $conn   = CONFIG::get('database.default');
        $config = CONFIG::get("database.connections.$conn");
        return ($key ? $config[$key] : $config);
    }

    protected static function checkCreateTokenDBUser(string $login, string $password): bool
    {
        $created  = FALSE;
        $database = self::configDatabase('database');
        $login    = preg_replace("/(['\"])/", '\\\$1', $login);
        $password = preg_replace("/(['\"])/", '\\\$1', $password);

        // Check for existence (PostGreSQL specific)
        $userExists = DB::select("SELECT 1 FROM pg_roles WHERE rolname='$login';");
        if ($userExists) {
            // TODO: Update the password
            // Delete
            if (FALSE) {
                DB::unprepared("REVOKE ALL ON ALL TABLES IN schema public from \"$login\";");
                DB::unprepared("REVOKE ALL ON schema public from \"$login\";");
                DB::unprepared("REVOKE ALL ON database \"$database\" from \"$login\";");
                DB::unprepared("REASSIGN OWNED BY \"$login\" TO postgres;");
                DB::unprepared("DROP USER if exists \"$login\";");
            }
        } else {
            // Create
            // TODO: Make RLS / table access configurable
            try {
                DB::unprepared("CREATE USER \"$login\" with password '$password';");
                DB::unprepared("GRANT ALL ON DATABASE \"$database\" TO \"$login\";");
                DB::unprepared("GRANT ALL ON SCHEMA public TO \"$login\";");
                DB::unprepared("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO \"$login\";");
                $created = TRUE;
            } catch (QueryException $ex) {
                Flash::error($ex->getMessage());
            }
        }

        return $created;
    }

    protected static function loginScreenPath(): string
    {
        // TODO: publish this resource to app
        $dir     = dirname(__FILE__);
        $docroot = app()->basePath();
        $path    = "$docroot/public/resources/login.php";
        if (!file_exists($path)) $path = "$dir/resources/login.php";
        return $path;
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


        Users::extendFormFields(function ($form, $model, $context) {
            // Only a super user can use these tools
            // on others accounts
            $authUser = BackendAuth::user();
            if ($authUser->is_superuser
                && $model->id != $authUser->id
            ) {
                // Defaults
                $model->acornassociated_grant_database_usage = TRUE;
                $model->acornassociated_grant_schema_usage = TRUE;
                $model->acornassociated_grant_tables_all = TRUE;
                $model->acornassociated_create_user = TRUE;

                $docroot   = app()->basePath();
                $moduleDir = str_replace($docroot, '~', dirname(__FILE__));
                $username  = self::configDatabase('username');
                $password  = self::configDatabase('password');
                if ($username != '<DBAUTH>' || $password != '<DBAUTH>') {
                    $form->addTabFields([
                        'hint_not_setup' => [
                            'label'   => '',
                            'tab'     => 'DB Auth',
                            'type'    => 'partial',
                            'path'    => "$moduleDir/models/_hint_not_setup",
                        ],
                    ]);
                }

                $form->addTabFields([
                    'description' => [
                        'label'   => '',
                        'tab'     => 'DB Auth',
                        'type'    => 'partial',
                        'span'    => 'right',
                        'path'    => "$moduleDir/models/_description", // This is a dummy, just to hold the comment
                        'comment' => '<p class="help-block">You are seeing this tab because you are a <strong>Super User</strong>.<br/>DB Auth forces login in to the database with the users login credentials, instead of hard-coded credentials in the .env file. The .env file should have &lt;DBAUTH&gt; for the DB_USERNAME/PASSWORD settings. Every user that wants to login to the database must therefore have a Database user with the correct privileges, not just an entry in the backend_users table.</p>',
                        'commentHtml' => TRUE,
                    ],
                    'acornassociated_grant_database_usage' => [
                        'label'   => 'Database usage privilege',
                        'tab'     => 'DB Auth',
                        'span'    => 'left',
                        'type'    => 'checkbox',
                        'comment' => 'Necessary for system usage',
                    ],
                    'acornassociated_grant_schema_usage' => [
                        'label'   => 'Schema usage privilege',
                        'tab'     => 'DB Auth',
                        'span'    => 'left',
                        'type'    => 'checkbox',
                        'comment' => 'Necessary for system usage',
                    ],
                    'acornassociated_grant_tables_all' => [
                        'label'   => 'All Tables privileges',
                        'tab'     => 'DB Auth',
                        'span'    => 'left',
                        'type'    => 'checkbox',
                    ],
                    'acornassociated_db_super_user' => [
                        'label'   => 'Make DB super-user',
                        'tab'     => 'DB Auth',
                        'span'    => 'left',
                        'type'    => 'checkbox',
                        'comment' => 'This will only be available if the user is marked as a super user in Winter',
                    ],
                    'acornassociated_create_user' => [
                        'label'   => 'Create and synchronise DB user',
                        'tab'     => 'DB Auth',
                        'span'    => 'left',
                        'type'    => 'checkbox',
                    ],
                ]);
            }
        });
    }
}