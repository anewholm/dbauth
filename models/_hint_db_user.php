<?php  
use DBAuth\PostGreSQLManager as DBManager;

$dbUser = DBManager::dbUserName($formModel);
?>
<div class="layout-row min-size">
    <div class="callout callout-info">
        <div class="header">
            <i class="icon-info"></i>
            <h3><?= e(trans('User identity in the database')) ?></h3>
            <p>
                <b><?= e($dbUser) ?></b> made from token_%id
            </p>
        </div>
    </div>
</div>
