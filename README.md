# DB Auth direct module
This module logs in to the database with the front-end user login credentials. Because of this no usernames/passwords are necessary on the webserver, in `config/database.php`.
After login Laravel creates a session token for further requests. At the same time this plugin creates a new database user with the same name as the session token and the same privileges as the original database user. Further database logins use this token database user. PostGreSQL RLS (Row Level Security) policies are recommended to restrict access to information in the database.

## Installation
`git clone` this module in to Laravel ~/modules.
Register the `DBAuth\ServiceProvider::class` in the `config/app.php` providers list.
Set the database username and password in `config/database.app` to "&lt;DYNAMIC&gt;" to trigger the plugin functionality.