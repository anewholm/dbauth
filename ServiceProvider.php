<?php namespace DBAuth;

use Illuminate\Support\Facades\App;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Session\SessionManager;
use DBAuth\PostGreSQLManager as DBManager;
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
use ApplicationException;
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

            Event::listen('backend.page.beforeDisplay', function($action, $params) {
                // After DB connected
                // Before Auth::Authenticate()'d against backend_users
                if (self::isLoggingIn()) {
                    // Auto check / create a backend_users Winter user
                    // for this successful DB login
                    $input = post();
                    self::checkCreateBackendUser($input['login'], $input['password']);
                }
                return FALSE; // Continue
            });

            // Check / Create a mirror token_$id database user 
            // upon successful login with main user credentials 
            Event::listen('backend.user.login', function($user) {
                // Login to database has been successful
                // A token has been generated for future connections
                // Create a new DB user for the login token
                // as we already have a DB connection that can create users
                // It is important that the main login has GRANT OPTION and CREATE ROLES
                return DBManager::checkCreateDBUser(
                    "token_" . (int) $user->id, 
                    $user->getPersistCode(),
                    $user->is_superuser,
                    $user->is_superuser
                );
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

            // Immediately test the connection
            // Note that the authorisation procedure has not happend yet
            // and we cannot get the username / id yet from session
            try {
                DB::unprepared("select 1");
            } catch (QueryException $ex) {
                self::showLoginScreen($ex);
            }
        }
    }

    public static function checkCreateBackendUser(string $username, string $password): User
    {
        $user = User::where('login', '=', $username)->first();
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
        return DBManager::configDatabase('username') == '<DBAUTH>';
    }

    protected static function isLoggingIn(): bool
    {
        $input = post();
        return (isset($input['login']) && isset($input['password']));
    }

    public static function morphConfig(array &$config): string|bool
    {
        // Note $config passed by reference
        // Return value of FALSE indicates no changes to config
        // so username may still == <DBAUTH>
        // causing connection failure
        $username    = FALSE;
        $input       = post();

        if (self::isLoggingIn()) {
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

        // Translate errors
        $exceptionMessage = NULL;
        if ($ex) {
            switch ($ex->getCode()) {
                case 7:
                    // Password authentication failed
                    $exceptionMessage = 'Password authentication failed.';
                    break;
                case 42501: 
                    // Insufficient privilege: 7 ERROR:  permission denied to create role
                    $exceptionMessage = 'Create roles privilege is required.';
                    break;
                default:
                    $exceptionMessage = $ex->getMessage();
            }
        }   

        // Show the fixed HTML login screen and exit
        // to avoid any db access attempts from other plugins
        include ServiceProvider::loginScreenPath();

        // Prevent any further execution
        // as it may well try to connect to the database
        // and we have no credentials to do so
        exit(0);
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
            if (is_a($model, User::class)) {
                $model->bindEvent('model.beforeSave', function () use ($model) {
                    // _tools & _db_privileges has sent through extra 
                    // non-Model settings
                    $input = input();
                    if ($input['acornassociated_create_user'] == 1) {
                        if ($input['dbauth_password']) {
                            DBManager::checkCreateDBUser(
                                $model->login, 
                                $input['dbauth_password'], 
                                $input['acornassociated_rolecreate'] == 1,
                                $model->is_superuser,
                                $input['acornassociated_withgrantoption'] == 1
                            );
                        } else {
                            throw new ApplicationException('Password required');
                        }
                    } else {
                        DBManager::checkDropDBUser($model->login);
                    }
                });
        
                // Only a super user can use these tools
                // on others accounts
                $authUser = BackendAuth::user();
                if ($authUser->is_superuser
                    && $model->id != $authUser->id
                ) {
                    $docroot   = app()->basePath();
                    $moduleDir = str_replace($docroot, '~', dirname(__FILE__));
                
                    // Hints
                    $username  = DBManager::configDatabase('username');
                    $password  = DBManager::configDatabase('password');
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
                    if (!DBManager::userExists($model->login)) {
                        $form->addTabFields([
                            'hint_no_db_user' => [
                                'label'   => '',
                                'tab'     => 'DB Auth',
                                'type'    => 'partial',
                                'path'    => "$moduleDir/models/_hint_no_db_user",
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
                            'comment' => '<p class="help-block">You are seeing this other users tab because you are a <strong>Super User</strong>.<br/>DB Auth forces login in to the database with the users login credentials, instead of hard-coded credentials in the <strong>.env</strong> file. The <strong>.env</strong> file should have &lt;DBAUTH&gt; for the <strong>DB_USERNAME</strong> / <strong>PASSWORD</strong> settings. Every user that wants to login to the database must therefore have a Database user with the correct privileges, not just an entry in the backend_users table.</p>',
                            'commentHtml' => TRUE,
                        ],
                        'user_tools' => [
                            'label'   => '',
                            'tab'     => 'DB Auth',
                            'type'    => 'partial',
                            'span'    => 'left',
                            'path'    => "$moduleDir/models/_user_tools",
                        ],
                        'db_privileges' => [
                            'label'   => '',
                            'tab'     => 'DB Auth',
                            'type'    => 'partial',
                            'span'    => 'right',
                            'path'    => "$moduleDir/models/_db_privileges",
                        ],
                    ]);
                }
            }
        });
    }
}