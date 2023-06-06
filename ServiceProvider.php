<?php namespace DBAuth;

use BackendAuth;
use AcornAssociated\Auth\Classes\DB;
use Event;

use Winter\Storm\Support\ModuleServiceProvider;
use Illuminate\Database\Connectors\ConnectionFactory;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Facades\Config;
use Form as FormHelper;

class ServiceProvider extends ModuleServiceProvider
{
    use \System\Traits\SecurityController;
    
    public function boot()
    {
        // ----------------------------- DB secure login
        app('db')->extend('pgsql', function($config, $name) {
            //$config['username'] = 'winter';
            //$config['password'] = 'QueenPool1@';

            if ($config['username'] == '<DYNAMIC>') {
                $input       = post();
                $isLoggingIn = (isset($input['login']) && isset($input['password']));
                if ($isLoggingIn) {
                    // Allow normal logging in process
                    // The backend.user.login event below will create a DB user
                    // for the resultant new login token
                    $config['username'] = $input['login'];
                    $config['password'] = $input['password'];
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
                        $config['username'] = "token_$id";
                        $config['password'] = $token;
                    } else {
                        // Show the fixed HTML login screen and exit
                        // to avoid any db access attempts from other plugins
                        // TODO: publish this resource to app
                        $dir     = dirname(__FILE__);
                        $docroot = $_SERVER['DOCUMENT_ROOT'];
                        $path    = "$docroot/public/resources/login.html";
                        if (!file_exists($path)) $path = "$dir/resources/login.html";
                        $html = file_get_contents($path);

                        // XSRF protection
                        $cookie = $this->makeXsrfCookie();
                        //setcookie($cookie->getName(), $cookie->getValue());
                        dump($cookie);
                        dump(Config::get('session'));
                        dump(9);
                        $html = str_replace('[SESSION_KEY]', FormHelper::getSessionKey(), $html);
                        $html = str_replace('[TOKEN]', Session::token(), $html);

                        // Login screen with XSRF
                        print($html);

                        // Prevent any further execution
                        // as it may well try to connect to the database
                        // and we have no credentials to do so
                        exit(0);
                    }
                }
            }

            dump($config);
            $factory = new ConnectionFactory(app());

            return $factory->make($config, $name);
        });

        // TODO: Upon successful DB login
        // check / create that the user is in backend_users
        // thus, only creation of DB users is necessary

        Event::listen('backend.user.login', function(User $user){
            // Login to database has been successful
            // A token has been generated for future connections
            // Create a new user for the login token
            // as we already have a DB connection that can create users
            // It is important that the main login has GRANT OPTION and CREATE ROLES
            // DB::createUser("token_" . (int) $user->id, $user->getPersistCode());
        });
    }
}