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
use Flash;
use Backend\Controllers\Users;
use SebastianBergmann\Type\VoidType;
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

    public static function tokenLoginName(User $backendUser): string
    {
        if (is_null($backendUser->id))
            throw new Exception('User has no ID during tokenLoginName()');
        return self::tokenLoginNameFromID($backendUser->id);
    }
    
    public static function tokenLoginNameFromID(int $id): string
    {
        // Database is included for multiple DB servers
        $database = DBManager::configDatabase('database');
        return "token_{$database}_$id";
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
            Event::listen('backend.user.login', function($user) {
                // Login to database has been successful with Normal user
                // A new backend_users.persist_code has been generated for future connections using the token_% user
                // The token_% password needs to be updated for this new persist code
                // It is necessary that the normal login has GRANT OPTION and CREATEROLE on the token_%
                // in order to make this change
                //   GRANT agri TO token_27 WITH ADMIN OPTION => agri can change token_27
                $success = NULL;
                try {
                    if (Settings::get('auto_create_db_user') == '1') {
                        $tokenLoginName = self::tokenLoginName($user);
                        $persistCode    = $user->getPersistCode();
                        $success = DBManager::updateDBPassword($persistCode, $tokenLoginName);
                    }
                } catch (QueryException $ex) {
                    // This will show the exception message
                    $this->showLoginScreen(NULL, $ex);
                }
    
                return $success;
            });

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
                $authUser = BackendAuth::user();

                // -------------------------- onSave create|update the DB user
                $user->bindEvent('model.afterSave', function () use(&$user) {
                    return $this->afterSave($user);
                });
                $user->bindEvent('model.afterDelete', function () use(&$user) {
                    return $this->afterDelete($user);
                });
                
                // -------------------------- Fields
                // Only a super user can use these tools
                // on others accounts so far
                $form->getController()->addViewPath('modules/dbauth/partials');
                $form->addTabFields($this->hints($user));
                $form->addTabFields($this->userFields());
                
                // DBAuth cannot allow logins to be changed currently
                // Disable the login field
                if ($user->exists) {
                    $field = $form->getField('login');
                    $field->disabled = true;
                    $field->comment  = 'dbauth::lang.models.user.login_fixed';
                }

                // Email
                $field = $form->getField('email');
                $field->comment  = 'dbauth::lang.models.user.email_optional';

                // Permissions to password fields
                $isMe = $user->is($authUser);
                if ($isMe && !$authUser->hasPermission('dbauth.backend.user_own_password_change')) {
                    $field = $form->getField('password');
                    $field->disabled = true;
                    $field->comment  = 'dbauth::lang.permissions.no_password_change_comment';
                    $form->getField('password_confirmation')->hidden = true;
                }
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

    public static function getSessionAuthCookieArray(): array|NULL
    {
        // Returns [backend_users.id, backend_users.persist_code]
        // An auth_token is the backend_users.persist_code
        //
        // Get the users id and auth token
        // from their browser client session / cookie
        // Laravel cookies are encrypted:
        //   EncryptCookies::decrypt(Request)
        //   Encrypter uses openssl_decrypt()
        //   helpers.php declares the generalised decrypt():
        //     app('encrypter')->decrypt($value, $unserialize);
        // Laravel decrypts the Session::* AFTER DB connection
        // so we have to do it manually here
        $authArray = NULL;
        try {
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
        } catch (Exception $ex) {
            // Potentially invalid JSON 
            // or other format problems
            $authArray = NULL;
        }

        // Validate
        if (!is_array($authArray) || count($authArray) != 2)
            $authArray = NULL;

        // [backend_user.id, backend_users.persist_code]
        return $authArray;
    }

    public function morphConfig(array $config): array
    {
        // Note $config passed by reference
        // Return value of FALSE indicates no changes to config
        // so username may still == <DBAUTH>
        // causing connection failure
        if ($this->isLoggingIn()) {
            // Allow normal logging in process
            $input = post();
            $config['username'] = $input['login'];
            $config['password'] = $input['password'];
        } else {
            ;
            if ($authArray = self::getSessionAuthCookieArray()) {
                // Note that a user with this token information
                // will have been created at the point of token creation
                //   Auth\Manager::setPersistCodeInSession()
                // using the Users actual original login credentials
                // to create the temporary user
                // So the DB user token_% needs to use the auth_token (persist code)
                // to login. We do not know the original password
                [$id, $token] = $authArray;
                $config['username'] = self::tokenLoginNameFromID($id);
                $config['password'] = $token; // Persist code
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
            //$sessionId = Session::getId();
            // This is likely an old backend persist token
            // causing failed token_% DB connect
            if ($ex) 
                BackendAuth::logout();
            Session::save();

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
                'cssClass' => 'col-xs-12 col-md-4',
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
                'cssClass' => 'col-xs-12 col-md-4',
                'permissions' => array('dbauth.setup_user'),
            ];

        if ($user->exists) {
            if (DBManager::dbUserExists($user->login)) {
                $hints['hint_db_user'] = [
                    'label'    => '',
                    'tab'      => self::$tab,
                    'type'     => 'partial',
                    'path'     => "hint_db_user",
                    'span'     => 'storm',
                    'cssClass' => 'col-xs-12 col-md-4',
                    'permissions' => array('dbauth.setup_user'),
                ];
                // Double check options
                $dbUserAttributes = DBManager::dbUserAttributes($user->login);
                if ($dbUserAttributes['SUPERUSER']) $hints['hint_db_user_login'] = [
                    'label'    => '',
                    'tab'      => self::$tab,
                    'type'     => 'partial',
                    'path'     => "hint_db_super_user",
                    'span'     => 'storm',
                    'cssClass' => 'col-xs-12 col-md-4',
                    'permissions' => array('dbauth.setup_user'),
                ];

                if (!$dbUserAttributes['LOGIN']) $hints['hint_db_user_login'] = [
                    'label'    => '',
                    'tab'      => self::$tab,
                    'type'     => 'partial',
                    'path'     => "hint_db_user_login",
                    'span'     => 'storm',
                    'cssClass' => 'col-xs-12 col-md-4',
                    'permissions' => array('dbauth.setup_user'),
                ];
                
                if (!$dbUserAttributes['CREATEROLE']) $hints['hint_db_user_createrole'] = [
                    'label'    => '',
                    'tab'      => self::$tab,
                    'type'     => 'partial',
                    'path'     => "hint_db_user_createrole",
                    'span'     => 'storm',
                    'cssClass' => 'col-xs-12 col-md-4',
                    'permissions' => array('dbauth.setup_user'),
                ];

                // Confirmation
                if ($dbUserAttributes['LOGIN'] && $dbUserAttributes['CREATEROLE']) $hints['hint_db_user_ok'] = [
                    'label'    => '',
                    'tab'      => self::$tab,
                    'type'     => 'partial',
                    'path'     => "hint_db_user_ok",
                    'span'     => 'storm',
                    'cssClass' => 'col-xs-12 col-md-4',
                    'permissions' => array('dbauth.setup_user'),
                ];
            } else {
                $hints['hint_no_db_user'] = [
                    'label'    => '',
                    'tab'      => self::$tab,
                    'type'     => 'partial',
                    'path'     => "hint_no_db_user",
                    'span'     => 'storm',
                    'cssClass' => 'col-xs-12 col-md-4',
                    'permissions' => array('dbauth.setup_user'),
                ];
            }
        }

        return $hints;
    }

    public function afterDelete(User $aBackendUser): void
    {
        $tokenLogin = self::tokenLoginName($aBackendUser); // token_%
        DBManager::checkDropDBUser($aBackendUser->login);
        DBManager::checkDropDBUser($tokenLogin);
    }

    public function afterSave(User $aBackendUser): void
    {
        // Scenarios:
        //   *) A DB (CREATEROLE+ADMIN/SUPERUSER) & Winter SUPERUSER is creating a new Backend user, necessarily with a password
        //   *) A DB (CREATEROLE+ADMIN/SUPERUSER) & Winter SUPERUSER is updating a Backend user, optionally changing the password
        //   *) A under-privileged user is updating their own password
        //   *) A under-privileged user is updating their own name or other values
        // The login field is always disabled because it cannot be changed after initial create currently
        // Winter SUPERUSERs should also be DB SUPERUSERs
        // At least CREATEROLE is required to create DB roles, +ADMIN OPTION to update them
        //
        // PostGreSQL can ALTER CURRENT_USER   WITH PASSWORD 'my-new-password' without special permissions checks
        // whereas        ALTER <my-user-name> WITH PASSWORD 'my-new-password' requires CREATEROLE and ADMIN on user
        // ALTER CURRENT_USER will only work without permission checks if _only_ the password is being updated
        // additional parameters like LOGIN will cause a permission check
        // DBManager::dbUserAttributes() provides into on DB user parameters like LOGIN & CREATEROLE
        // In order for DB info to be gained, CURRENT_USER read access to the pg_roles _view_ is necessary
        //
        // There are 2 DB users that require updating: the normal login and token_%
        // Password updates need to happen on both
        // However, CURRENT_USER will always be the token_% DB user
        // so access to the original normal login conditional on a permission check
        // both CREATEROLE and ADMIN option on the normal user are required
        // Users *will* have to make an initial login with the normal user again 
        // once their user_id cookie => token_% is expired or not available
        $authUser        = BackendAuth::user();
        $isCurrentUser   = $aBackendUser->is($authUser);
        // Privilege to update other users? Rather than just SUPERUSER?
        $canUpdateOthers = $authUser->is_superuser;
        $tokenLogin      = self::tokenLoginName($aBackendUser); // token_%

        if ($isCurrentUser) {
            $dbCURRENT_USER = DBManager::dbCURRENT_USER();
            if ($aBackendUser->id != $authUser->id)
                throw new Exception("Auth ID [$authUser->id] is not the same as the backend user ID [$aBackendUser->id] during isCurrentUser mode update");
            if ($tokenLogin != $dbCURRENT_USER)
                throw new Exception("DB CURRENT_USER [$dbCURRENT_USER] is not the token backend user [$tokenLogin] during isCurrentUser mode update");
        }
        
        if ($canUpdateOthers || $isCurrentUser) {
            $purgeValues     = $aBackendUser->getOriginalPurgeValues();
            $password        = (isset($purgeValues['password_confirmation']) ? $purgeValues['password_confirmation'] : NULL);
            $oldPassword     = (isset($purgeValues['_acorn_dbauth_password']) ? $purgeValues['_acorn_dbauth_password'] : NULL);
            $isSyncing       = ($aBackendUser->acorn_create_sync_user == '1');
            $autoCreateUser  = (Settings::get('auto_create_db_user') == '1');

            if ($isSyncing && $autoCreateUser) {
                // --------------------------------------- Initial creates
                if (!DBManager::dbUserExists($aBackendUser->login)) {
                    // Normal initial login, login cannot be changed after
                    if (!$password)
                        throw new Exception("Cannot create DB user [$aBackendUser->login] becaues initial password not provided");
                    $created = DBManager::createDBUser(
                        $aBackendUser->login, 
                        $password,
                        // SUPERUSER Not necessary because token_% login is used 
                        FALSE, 
                        // Needs to update token_% during login
                        TRUE,
                        $purgeValues // GRANTS
                    );
                }

                if (!DBManager::dbUserExists($tokenLogin)) {
                    // token_% based on backend_user.id. Does not change after
                    $created = DBManager::createDBUser(
                        $tokenLogin, 
                        // password / persistCode updated during login above
                        $aBackendUser->getRandomString(), 
                        $aBackendUser->is_superuser,
                        // Does not need to make any changes to other users
                        FALSE,
                        $purgeValues, // GRANTS
                        // This will allow the token_% user to change the normal users password
                        // CREATEROLE + ADMIN OPTION on normal login for unprivileged password updates
                        array($aBackendUser->login)
                    );
                }

                // --------------------------------------- Update
                // Remember we are logged in with the/a token_% user, not this one
                if ($password) {
                    // Password has been changed in backend_users
                    // Update the normal DB user
                    // We are never this user, only token_% or another (super)user
                    // This requires SUPERUSER 
                    // or token_% CREATEROLE and ADMIN OPTION for the CURRENT_USER on the normal role
                    // However, we do not grant ADMIN OPTION to the token_% role
                    // So the old password will be required in this case
                    try {
                        DBManager::updateDBPassword($password, $aBackendUser->login, $oldPassword);
                    } catch(Exception $ex) {
                        if ($oldPassword) {
                            switch ($ex->getCode()) {
                                case 7: // password authentication failed
                                    $messageNice = trans('dbauth::lang.models.user.failed_login');
                                    if (env('APP_DEBUG')) {
                                        $message = $ex->getMessage();
                                        $messageNice .= " $message";
                                    }
                                    // TODO: Maybe move this to a Flash in beforeSave()?
                                    throw new Exception($messageNice);
                                    break;
                                default: 
                                    throw $ex;
                            }
                        } else {
                            throw new Exception("Password update of [$aBackendUser->login] failed. Please try again sending the old password as well");
                        }
                    }
                }

                if ($aBackendUser->isDirty('is_superuser')) {
                    // Normal login does not have to be a SUPERUSER because it is not used
                    // after initial login
                    if ($aBackendUser->is_superuser) DBManager::makeSUPERUSER( $tokenLogin);
                    else                             DBManager::clearSUPERUSER($tokenLogin);
                }
            } else {
                // Tidy up
                DBManager::checkDropDBUser($aBackendUser->login);
                DBManager::checkDropDBUser($tokenLogin);
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
        $fields   = array();
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
                'type'     => 'sensitive',
                'span'     => 'left',
                'comment'  => 'dbauth::lang.models.user.dbauth_password_comment',
                'commentHtml' => TRUE,
                'attributes'  => array('autocomplete' => 'off'),
            );
        }

        $fields = array_merge($fields, array(
            'acorn_create_sync_user' => [
                'label'    => 'dbauth::lang.models.user.sync_user',
                'type'     => 'switch',
                'tab'      => self::$tab,
                'default'  => true,
                'span'     => 'storm',
                'cssClass' => 'col-xs-4',
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

            // Schema usage etc.
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
            'dbauth.backend.user_own_password_change' => [
                'tab'   => 'acorn::lang.permissions.tab',
                'label' => 'dbauth::lang.permissions.user_own_password_change'
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
