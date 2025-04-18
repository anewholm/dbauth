<?php  
use DBAuth\PostGreSQLManager as DBManager;

$dbCURRENT_USER = DBManager::dbCURRENT_USER();
?>
<div class="layout-row min-size">
    <div class="callout callout-info">
        <div class="header">
            <i class="icon-info"></i>
            <h3><?= e(trans('Current user identity in the database')) ?></h3>
            <p>
                <b><?= e($dbCURRENT_USER) ?></b> made from token_%id
            </p>
        </div>
    </div>
</div>
