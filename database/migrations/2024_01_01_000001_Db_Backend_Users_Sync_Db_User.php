<?php

use Winter\Storm\Database\Schema\Blueprint;
use Acorn\Migration;

class DbBackendUsersSyncDbUser extends Migration
{
    public function up()
    {
        // Add extra namespaced fields in to the backend_users table
        Schema::table('backend_users', function(Blueprint $table) {
            if (!Schema::hasColumn($table->getTable(), 'acorn_create_sync_user')) 
                $table->boolean('acorn_create_sync_user')->default(TRUE);
        });

        // View for current user details
        $this->createView('acorn_dbauth_user', <<<BODY
            select bk.id as backend_id, bk.login as backend_login, 
            u.*
            from backend_users bk 
            inner join acorn_user_users u on bk.acorn_user_user_id = u.id 
            where bk.id = case 
                when CURRENT_USER ~ '^token_[0-9]+$' then replace(CURRENT_USER, 'token_', '')::int
                else NULL
            end;
BODY
        );
    }

    public function down()
    {
        Schema::table('backend_users', function(Blueprint $table) {
            if (Schema::hasColumn($table->getTable(), 'acorn_create_sync_user')) 
                $table->dropColumn('acorn_create_sync_user');
        });
    }
}
