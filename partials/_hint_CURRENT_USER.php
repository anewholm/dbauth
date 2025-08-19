<?php  
use DBAuth\PostGreSQLManager as DBManager;

$dbCURRENT_USER = DBManager::dbCURRENT_USER();
?>
<div class="layout-row min-size">
    <div class="callout callout-info">
        <div class="header">
            <i class="icon-info"></i>
            <h3><?= e(trans('dbauth::lang.hints.current_user')) ?></h3>
            <p><b><?= e($dbCURRENT_USER) ?></b> <?= e(trans('dbauth::lang.hints.made_from_token')) ?></p>
        </div>
    </div>
</div>
