<?php  
use DBAuth\PostGreSQLManager as DBManager;

$dbUser = DBManager::dbUserName($formModel);
?>
<div class="layout-row min-size">
    <div class="callout callout-info">
        <div class="header">
            <i class="icon-info"></i>
            <h3><?= e(trans('dbauth::lang.hints.user_identity')) ?></h3>
            <p><b><?= e($dbUser) ?></b> <?= e(trans('dbauth::lang.hints.made_from_token')) ?></p>
        </div>
    </div>
</div>
