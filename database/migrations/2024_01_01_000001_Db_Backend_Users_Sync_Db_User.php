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
            select bk.id as backend_id, bk.login as backend_login, u.*
            from backend_users bk 
            inner join acorn_user_users u on bk.acorn_user_user_id = u.id 
            where bk.id = CASE 
                WHEN CURRENT_USER ~ ('^token_' || CURRENT_DATABASE() || '_[0-9]+$'::text) 
                    THEN replace(CURRENT_USER::text, 'token_'::text || CURRENT_DATABASE() || '_', ''::text)::integer
                else NULL
            END;
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
