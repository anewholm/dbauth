<?php namespace DBAuth;

use Illuminate\Support\Facades\App;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Session\SessionManager;
use DBAuth\PostGreSQLManager as DBManager;
use DBAuth\Models\Settings;
use BackendAuth;
use Event;
use Exception;
use DB;
use File;
use Lang;
use Auth;
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
use Winter\Storm\Exception\ApplicationException;
use DBAuth\Console\SetupAccess;

class ServiceProvider extends ModuleServiceProvider
{
    use \System\Traits\SecurityController;
    
    static $tab = 'dbauth::lang.module.name';

    // ----------------------------------------------------- Status
    protected function isEnabled(): bool
    {
        // config/database.php username=<DBAUTH> necessary for this functionality 
        return DBManager::configDatabase('username') == '<DBAUTH>';
    }

    protected function isLoggingIn(): bool
    {
        $input = post();
        return (isset($input['login']) && isset($input['password']));
    }

    public function boot()
    {
        // Register localization
        Lang::addNamespace('dbauth', realpath('modules/dbauth/lang'));

        User::extend(function ($model) {
            // Remove the requirements for unique emails
            // This allows an empty string for the email
            unset($model->rules['email']);
        });

        if ($this->isEnabled()) {
            // TODO: SECURITY: Disabled this because I cannot get XSRF to work
            // on the login form
            Config::set('cms.enableCsrfProtection', false);

            // ---------------------------------------  Login control
            Event::listen('backend.page.beforeDisplay', function($action, $params) {
                // After DB connected
                // Before Auth::Authenticate()'d against backend_users
                if ($this->isLoggingIn()) {
                    // Auto check / create a backend_users Winter user
                    // for this successful DB login
                    $input = post();
                    $this->checkCreateBackendUser($input['login'], $input['password']);
                }
            });

            // Check / Create a mirror token_$id database user 
            // upon successful login with main user credentials 
            Event::listen('backend.user.login', function($user) {
                // Login to database has been successful
                // A token has been generated for future connections
                // Create a new DB user for the login token
                // as we already have a DB connection that can create users
                // It is important that the main login has GRANT OPTION and CREATE ROLES
                // TODO: Re-visit all these GRANTS!!!
                try {
                    $autoCreateUser  = (Settings::get('auto_create_db_user') == '1');
                    if ($autoCreateUser) {
                        $created = DBManager::upCreateDBUser(
                            DBManager::dbUserName($user), // token_%
                            $user->getPersistCode(),
                            $user->is_superuser, // CREATEROLE
                            $user->is_superuser, // SUPERUSER
                            $user->is_superuser, // WITH GRANT
                            array("all" => TRUE)
                        );
                    }
                } catch (QueryException $ex) {
                    // This will show the exception message
                    $this->showLoginScreen(NULL, $ex);
                }
    
                return $created;
            });

            // Trap Session / Cookie admin_auth on subsequent requests
            // to login with the token_$id user
            // TODO: This is also done in register() so artisan runs it. Maybe delete this one
            app('db')->extend('pgsql', function($config, $name){
                $config = $this->morphConfig($config);

                // If neither a login, nor a token
                // then config will still == <DBAUTH>
                // so we cannot connect to the database
                if ($config['username'] == '<DBAUTH>') {
                    // showLoginScreen() may exit()
                    // However, if this is artisan, it might return a username
                    $config = $this->showLoginScreen($config);
                    if ($config['username'] == '<DBAUTH>') 
                        throw new PDOException("No username provided for database connection");
                }

                // Connect with the Config::* morphed credentials
                $connFactory = new ConnectionFactory(app());
                return $connFactory->make($config, $name);
            });

            // Immediately test the connection
            // Note that the authorisation procedure has not happend yet
            // and we cannot get the username / id yet from session
            // TODO: Should this test be only APP_DEBUG?
            try {
                // Force reconnect to trigger the pgsql extend above
                // We use winter_translate_attributes because it is necessary for frontend default user
                // and we want to catch any problems it might have
                if ($this->app->runningInConsole()) DB::reconnect();
                DB::unprepared("select 1 from winter_translate_messages limit 1");
            } catch (QueryException $ex) {
                // If it is running in the front-end
                // then showLoginScreen() will simply throw the exception
                // but with good details if APP_DEBUG
                $this->showLoginScreen(NULL, $ex);
            }
        }

        // --------------------------------------- Extend Backend users fields and columns for management
        Users::extendListColumns(function ($list, $user) {
            if ($user instanceof User) {
                $authUser = BackendAuth::user();
                if ($authUser && $authUser->is_superuser) {
                    $list->addColumns($this->userColumns());
                }
            }
        });

        Users::extendFormFields(function ($form, $user, $context) {
            if ($user instanceof User) {
                // -------------------------- onSave create the DB user
                $user->bindEvent('model.beforeSave', function () use(&$user) {
                    return $this->beforeSave($user);
                });
                
                // -------------------------- Fields
                // Only a super user can use these tools
                // on others accounts so far
                // TODO: Users changing their own username and password
                $form->getController()->addViewPath('modules/dbauth/partials');
                $form->addTabFields($this->hints($user));
                $form->addTabFields($this->userFields());
                
                // TODO: Add permissions to password fields
                // $field = $form->getField('password_confirmation');
                // $field->permissions = array('acorn.user.user_password_confirmation_view', 'acorn.user.user_password_confirmation_change');
            }
        });

        BackendAuth::registerCallback(function ($manager) {
            $manager->registerPermissions('DBAuth', $this->registerPermissions());
        });

        // VERSION: Winter 1.2.6: send also parameter ('dbauth');
        // But does not seem to cause a problem if ommitted
        parent::boot();
    }

    public function checkCreateBackendUser(string $username, string $password): User
    {
        // Database connection was successful
        // with a PostGres DB user with the sent user/pass
        // Backend\Models\User (backend_users)
        $autoCreateBackendUser = (Settings::get('auto_create_backend_user') == '1');
        if ($autoCreateBackendUser) {
            $user = User::where('login', '=', $username)->first();
            if (is_null($user)) {
                // backend_users record not there
                // JIT for login procedure
                $user = User::create([
                    'login'      => $username,
                    'first_name' => $username,
                    'email'      => '',
                    'password'   => $password,
                    'password_confirmation' => $password,
                ]);
            } else if (!$user->checkPassword($password)) {
                // Hash::check($password, $this->password);
                // Password is wrong. Adjust it!"$username@nowhere.com"
                $user->password = $password; // =>setPasswordAttribute()
                $user->password_confirmation = $password;
                $user->save();
            }
        }

        return $user;
    }

    public function morphConfig(array $config): array
    {
        // Note $config passed by reference
        // Return value of FALSE indicates no changes to config
        // so username may still == <DBAUTH>
        // causing connection failure
        if ($this->isLoggingIn()) {
            // Allow normal logging in process
            // The backend.user.login event will create a DB user
            // for the resultant new login token
            $input = post();
            $config['username'] = $input['login'];
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
                $config['username'] = "token_$id";
                $config['password'] = $token;
            }
        }

        return $config;
    }

    public function showLoginScreen(?array $config = array(), ?PDOException $ex = NULL): array
    {
        // Translate errors
        $exceptionMessage = NULL;
        $resolution       = NULL;
        if ($ex) {
            $serverMessage = $ex->getMessage();
            $subCode       = (isset($ex->errorInfo[0]) ? $ex->errorInfo[0] : NULL);
            switch ($ex->getCode()) {
                case 7:     // Password authentication failed or not permitted to log in
                    if (strstr($serverMessage, 'not permitted to log in')) {
                        $exceptionMessage = Lang::get('dbauth::lang.errors.login_not_permitted');
                        $resolution       = 'ALTER ROLE <user> WITH LOGIN;';
                    } else {
                        $exceptionMessage = Lang::get('dbauth::lang.errors.password_auth_failed');
                        $resolution       = 'ALTER ROLE <user> WITH PASSWORD \'<correct password>\';';
                    }
                    break;
                case 42501: // Insufficient privilege: 7 ERROR: permission denied to create token_%id role
                    $exceptionMessage = Lang::get('dbauth::lang.errors.create_role_required');
                    break;
                default:    // Generic response to not reveal info
                    $exceptionMessage = Lang::get('dbauth::lang.errors.generic_access_denied');
            }
            if (env('APP_DEBUG')) {
                $exceptionMessage .= ": $serverMessage $resolution";
                $connConfig        = DB::connection()->getConfig();
                $exceptionMessage .= " Connecting as user $connConfig[username] with password [$connConfig[password]]";
            }
        }   

        if ($this->app->runningInConsole()) {
            if ($exceptionMessage) print("\e[1;37;41m$exceptionMessage\e[0m\n");

            $username = NULL;
            $password = NULL;
            if (env('ARTISAN_AUTO_LOGIN')) {
                $username = 'artisan';
                $password = 'QueenPool1@';
            } else {
                print("\e[1;37;40mDB Auth is active.\e[0m ");
                print("So no database connection credentials are available in .env.\n");
                print("If you set .env \e[1;37;40mARTISAN_AUTO_LOGIN=1\e[0m then artisan will auto-login with winter/QueenPool1@\n");
                print("\e[32mDatabase username\e[0m [winter]: ");
                $username = (readline() ?: 'winter');
                print("\e[32mDatabase password\e[0m [QueenPool1@]: ");
                $password = (readline() ?: 'QueenPool1@');
            }
            $config['username'] = $username;
            $config['password'] = $password;
        } 
        
        else { // HTTP call
            // TODO: SECURITY: XSRF protection is disabled above
            Session::start(); // => loadSession() && regenerateToken();
            //$cookie = $this->makeXsrfCookie();
            //setcookie($cookie->getName(), $cookie->getValue());
            $xsrf = Session::token();
            Session::save();
            //$sessionId = Session::getId();

            if ($this->app->runningInBackend()) {            
                // Show the fixed HTML login screen and exit
                // to avoid any db access attempts from other plugins
                include $this->loginScreenPath();
                // Prevent any further execution
                // as it may well try to connect to the database
                // and we have no credentials to do so
                exit(0);
            } 
            else {
                // Well, it is a front-end request
                // which does NOT mean there is a front-end necessarily
                // The login will fail if not
                $config['username'] = 'frontend';
                $config['password'] = 'Fvv%#6nDFbR23';

                // We have a system issue if frontend cannot access the database
                if ($ex) {
                    // throw new Exception($exceptionMessage);
                    Auth::logout();
                }
            }
        }

        return $config;
    }

    protected function loginScreenPath(): string
    {
        // TODO: publish this resource to app
        $dir     = dirname(__FILE__);
        $docroot = $this->app->basePath();
        $path    = "$docroot/public/resources/login.php";
        if (!File::exists($path)) 
            $path = "$dir/resources/login.php";
        return $path;
    }

    // ----------------------------------------------------- User administration
    public function register()
    {
        parent::register();

        // Trap Session / Cookie admin_auth on subsequent requests
        // to login with the token_$id user
        // TODO: This is also done in boot() but artisan does not run it. Maybe delete that one
        app('db')->extend('pgsql', function($config, $name){
            $config = $this->morphConfig($config);

            // If neither a login, nor a token
            // then config will still == <DBAUTH>
            // so we cannot connect to the database
            if ($config['username'] == '<DBAUTH>') {
                // showLoginScreen() may exit()
                // However, if this is artisan, it might return a username
                $config = $this->showLoginScreen($config);
                if ($config['username'] == '<DBAUTH>') 
                    throw new PDOException("No username provided for database connection");
            }

            // Connect with the Config::* morphed credentials
            $connFactory = new ConnectionFactory(app());
            return $connFactory->make($config, $name);
        });

        $this->registerConsoleCommand('dbauth.setup-access', SetupAccess::class);

        SettingsManager::instance()->registerCallback(function ($manager) {
            $manager->registerSettingItems('Winter.Backend', $this->registerSettings());
        });
    }

    public function hints(User $user): array
    {
        $hints = array();

        $username      = DBManager::configDatabase('username');
        $password      = DBManager::configDatabase('password');
        
        if ($username != '<DBAUTH>' || $password != '<DBAUTH>')
            $hints['hint_not_setup'] = [
                'label'    => '',
                'tab'      => self::$tab,
                'type'     => 'partial',
                'path'     => "hint_not_setup",
                'span'     => 'storm',
                'cssClass' => 'col-xs-4',
                'permissions' => array('dbauth.setup_user'),
            ];

        if ($username == 'winter'
            && strstr($password, 'Quee') !== FALSE
            && strstr($password, 'Poo')  !== FALSE
        )
            $hints['hint_dev_setup'] = [
                'label'    => '',
                'tab'      => self::$tab,
                'type'     => 'partial',
                'path'     => "hint_dev_setup",
                'span'     => 'storm',
                'cssClass' => 'col-xs-4',
                'permissions' => array('dbauth.setup_user'),
            ];

        if ($user->exists) {
            if (DBManager::userExists($user->login)) {
                $hints['hint_db_user'] = [
                    'label'    => '',
                    'tab'      => self::$tab,
                    'type'     => 'partial',
                    'path'     => "hint_db_user",
                    'span'     => 'storm',
                    'cssClass' => 'col-xs-4',
                    'permissions' => array('dbauth.setup_user'),
                ];
                // Double check options
                $dbUserAttributes = DBManager::dbUserAttributes($user->login);
                if (!$dbUserAttributes['LOGIN']) $hints['hint_db_user_login'] = [
                    'label'    => '',
                    'tab'      => self::$tab,
                    'type'     => 'partial',
                    'path'     => "hint_db_user_login",
                    'span'     => 'storm',
                    'cssClass' => 'col-xs-4',
                    'permissions' => array('dbauth.setup_user'),
                ];
                if (!$dbUserAttributes['CREATEROLE']) $hints['hint_db_user_createrole'] = [
                    'label'    => '',
                    'tab'      => self::$tab,
                    'type'     => 'partial',
                    'path'     => "hint_db_user_createrole",
                    'span'     => 'storm',
                    'cssClass' => 'col-xs-4',
                    'permissions' => array('dbauth.setup_user'),
                ];
            } else {
                $hints['hint_no_db_user'] = [
                    'label'    => '',
                    'tab'      => self::$tab,
                    'type'     => 'partial',
                    'path'     => "hint_no_db_user",
                    'span'     => 'storm',
                    'cssClass' => 'col-xs-4',
                    'permissions' => array('dbauth.setup_user'),
                ];
            }
        }

        return $hints;
    }

    public function beforeSave(User $user): void
    {
        $authUser = BackendAuth::user();
        if ($authUser->is_superuser) {
            $purgeValues     = $user->getOriginalPurgeValues();
            $dbauthPassword  = (isset($purgeValues['_acorn_dbauth_password']) && $purgeValues['_acorn_dbauth_password'] ? $purgeValues['_acorn_dbauth_password'] : NULL);
            $createPassword  = (isset($purgeValues['password_confirmation'])            && $purgeValues['password_confirmation'] ? $purgeValues['password_confirmation'] : NULL);
            $roleCreate      = (isset($purgeValues['_acorn_rolecreate'])      && $purgeValues['_acorn_rolecreate']      == '1');
            $withGrantOption = (isset($purgeValues['_acorn_withgrantoption']) && $purgeValues['_acorn_withgrantoption'] == '1');
            $isSyncing       = ($user->acorn_create_sync_user == '1');
            // Update: DBAuth password (because we do not know what it was on create)
            // Create: Normal password
            // TODO: We do not understand now why _acorn_dbauth_password is necessary
            // because:
            //   1) we are ALTERing the password on our own CURRENT_USER
            //   2) we are a SUPERUSER ALTERing the password on someone else ROLE
            // $password        = ($dbauthPassword ?: $createPassword);
            $password        = $createPassword;
            $autoCreateUser  = (Settings::get('auto_create_db_user') == '1');

            if ($isSyncing && $autoCreateUser) {
                try {
                    // Will also try to sync the password if the user already exists
                    $created = DBManager::upCreateDBUser(
                        $user->login, 
                        $password, // Can be empty. Will still work if ALTER NOT CREATE
                        $roleCreate,
                        $user->is_superuser,
                        $withGrantOption,
                        $purgeValues
                    );

                    // TODO: Double save() because this will trigger another save() 
                    // and return here:
                    // getPersistCode() => $this->forceSave();
                    $persistCode = $user->getPersistCode();

                    // Update/Create the token_% user as well
                    $created = DBManager::upCreateDBUser(
                        DBManager::dbUserName($user), // token_%
                        $persistCode,
                        $user->is_superuser,  // CREATEROLE
                        $user->is_superuser,     // SUPERUSER
                        $user->is_superuser, // WITH GRANT
                        array("all" => TRUE)
                    );
                } catch (QueryException $ex) {
                    throw new ApplicationException($ex->getMessage());
                }
            } else {
                DBManager::checkDropDBUser($user->login);
            }
        }
    }

    public function userColumns(): array
    {
        return [
            'acorn_create_sync_user' => [
                'label' => 'dbauth::lang.models.user.sync_user',
                'type'  => 'partial',
                'path'  => 'modules/dbauth/partials/tick',
            ],
        ];
    }

    public function userFields(): array
    {
        $fields = array();

        $authUser = BackendAuth::user();
        // Only when the user themselves needs to update their info
        // and only if the user does not have CREATEROLE privilege
        // do they need to state their original database password
        // for the user that can connection and change roles
        //
        // When a SUPERUSER admin is updating someone else ROLE
        // then they do not need this because they have access to the ROLE with CREATEROLE
        if (!$authUser->is_superuser) {
            $fields['_acorn_dbauth_password'] = array(
                'label'    => 'dbauth::lang.models.user.dbauth_password',
                'tab'      => self::$tab,
                'type'     => 'sensitive',
                'required' => true,
                'span'     => 'storm',
                'cssClass' => 'col-xs-3',
                'comment'  => 'dbauth::lang.models.user.dbauth_password_comment',
                'commentHtml' => TRUE,
                'attributes'  => array('autocomplete' => 'off'),
                'context'  => 'update',
                'permissions' => array('dbauth.setup_user'),
            );
        }

        $fields = array_merge($fields, array(
            'acorn_create_sync_user' => [
                'label'    => 'dbauth::lang.models.user.sync_user',
                'type'     => 'switch',
                'tab'      => self::$tab,
                'default'  => true,
                'span'     => 'storm',
                'cssClass' => 'col-xs-3',
                'comment'  => 'dbauth::lang.models.user.sync_user_comment',
                'commentHtml' => TRUE,
                'attributes'  => array('autocomplete' => 'off'),
                'permissions' => array('dbauth.setup_user'),
            ],
            '_description' => [
                'label'    => '',
                'type'     => 'section',
                'tab'      => self::$tab,
                'span'     => 'storm',
                'cssClass' => 'col-xs-12 new-row',
                'comment'  => 'dbauth::lang.module.description',
                'commentHtml' => TRUE,
                'permissions' => array('dbauth.setup_user'),
            ],

            // DB privileges for token
            '_acorn_rolecreate' => [
                'label'    => 'dbauth::lang.models.user.rolecreate',
                'type'     => 'checkbox',
                'tab'      => self::$tab,
                'required' => true,
                'span'     => 'storm',
                'cssClass' => 'col-xs-12 col-md-4 new-row',
                'attributes' => array('autocomplete' => 'off', 'checked' => true),
                'comment'  => 'dbauth::lang.models.user.rolecreate_comment',
                'permissions' => array('dbauth.setup_user'),
            ],
            '_acorn_withgrantoption' => [
                'label'    => 'dbauth::lang.models.user.withgrantoption',
                'type'     => 'checkbox',
                'tab'      => self::$tab,
                'span'     => 'storm',
                'cssClass' => 'col-xs-12 col-md-4',
                'attributes' => array('autocomplete' => 'off', 'checked' => true),
                'comment'  => 'dbauth::lang.models.user.withgrantoption_comment',
                'commentHtml' => TRUE,
                'permissions' => array('dbauth.setup_user'),
            ],
            '_acorn_db_super_user' => [
                'label'   => 'dbauth::lang.models.user.db_super_user',
                'type'    => 'checkbox',
                'tab'     => self::$tab,
                'span'    => 'storm',
                'cssClass' => 'col-xs-12 col-md-4',
                'attributes' => array('autocomplete' => 'off'),
                'comment' => 'dbauth::lang.models.user.db_super_user_comment',
                'commentHtml' => TRUE,
                'permissions' => array('dbauth.setup_user'),
            ],
            
            // Schema usage etc.
            '_acorn_grants' => [
                'label'   => 'dbauth::lang.models.user.grants',
                'type'    => 'section',
                'tab'     => self::$tab,
                'comment'  => 'dbauth::lang.models.user.grants_comment',
                'commentHtml' => TRUE,
                'permissions' => array('dbauth.setup_user'),
            ],
            '_acorn_grant_database_usage' => [
                'label'   => 'dbauth::lang.models.user.grant_database_usage',
                'type'    => 'checkbox',
                'tab'     => self::$tab,
                'required' => true,
                'span'    => 'storm',
                'cssClass'   => 'col-xs-12 col-md-4',
                'attributes' => array('autocomplete' => 'off', 'checked' => true),
                'comment' => 'dbauth::lang.models.user.grant_database_usage_comment',
                'permissions' => array('dbauth.setup_user'),
            ],
            '_acorn_grant_schema_usage' => [
                'label'   => 'dbauth::lang.models.user.schema_usage',
                'type'    => 'checkbox',
                'tab'     => self::$tab,
                'required' => true,
                'span'    => 'storm',
                'cssClass'   => 'col-xs-12 col-md-4',
                'attributes' => array('autocomplete' => 'off', 'checked' => true),
                'comment' => 'dbauth::lang.models.user.schema_usage_comment',
                'permissions' => array('dbauth.setup_user'),
            ],
            '_acorn_grant_tables_all' => [
                'label'   => 'dbauth::lang.models.user.grant_tables_all',
                'type'    => 'checkbox',
                'tab'     => self::$tab,
                'span'    => 'storm',
                'cssClass' => 'col-xs-12 col-md-4',
                'attributes' => array('autocomplete' => 'off', 'checked' => true),
                'permissions' => array('dbauth.setup_user'),
            ],
            '_acorn_grant_sequences_all' => [
                'label'    => 'dbauth::lang.models.user.grant_sequences_all',
                'type'     => 'checkbox',
                'tab'      => self::$tab,
                'span'     => 'storm',
                'cssClass' => 'col-xs-12 col-md-4',
                'attributes' => array('autocomplete' => 'off', 'checked' => true),
                'comment'  => 'dbauth::lang.models.user.grant_sequences_all_comment',
                'commentHtml' => TRUE,
                'permissions' => array('dbauth.setup_user'),
            ],
            '_acorn_grant_functions_all' => [
                'label'   => 'dbauth::lang.models.user.grant_functions_all',
                'type'    => 'checkbox',
                'tab'     => self::$tab,
                'span'    => 'storm',
                'cssClass' => 'col-xs-12 col-md-4',
                'attributes' => array('autocomplete' => 'off', 'checked' => true),
                'permissions' => array('dbauth.setup_user'),
            ],
        ));

        return $fields;
    }

    public function registerPermissions(): array
    {
        return [
            'dbauth.setup_user' => [
                'tab'   => 'acorn::lang.permissions.tab',
                'label' => 'dbauth::lang.permissions.setup_user'
            ],
            'dbauth.manage_settings' => [
                'tab'   => 'acorn::lang.permissions.tab',
                'label' => 'dbauth::lang.permissions.manage_settings'
            ],
        ];
    }
    
    public function registerSettings(): array
    {
        return [
            'dbauth' => [
                'label'       => 'DataBase Authorisation settings',
                'description' => 'Manage direct database authorisation setup.',
                'category'    => 'system::lang.system.categories.system',
                'icon'        => 'icon-cog',
                'class'       => 'DBAuth\Models\Settings',
                'order'       => 500,
                'keywords'    => 'security database',
                'permissions' => ['dbauth.manage_settings']
            ]
        ];
    }
}
