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
    }

    public function down()
    {
        Schema::table('backend_users', function(Blueprint $table) {
            if (Schema::hasColumn($table->getTable(), 'acorn_create_sync_user')) 
                $table->dropColumn('acorn_create_sync_user');
        });
    }
}
