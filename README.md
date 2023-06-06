# DB Auth direct module
This module logs in to the database with the front-end user login credentials. Because of this no usernames/passwords are necessary on the webserver, in `config/database.php`.
After login Laravel creates a session token for further requests. At the same time this plugin creates a new database user with the same name as the session token and the same privileges as the original database user. Further database logins use this token database user. PostGreSQL RLS (Row Level Security) policies are recommended to restrict access to information in the database.

DBAuth only supports PostGreSQL.

## Installation
`git clone` this module in to Laravel `~/modules`.
Register the `DBAuth\ServiceProvider::class` in the `config/app.php` providers list.
Set the database username and password in `config/database.app` to "&lt;DYNAMIC&gt;" to trigger the plugin functionality.

## Login screen
DBAuth presents its own static HTML login screen because it needs to ensure that no attempts are made to access the database before login is successful. Laravels normal bootstrap and login screen process is likely to try and connect to the database. However, before DBAuth login, the database cannot be accessed. You can author your own version of the login screen by writing the `~/public/resources/login.html`.