<?php
$username  = DBAuth\PostGreSQLManager::configDatabase('username');
$password  = DBAuth\PostGreSQLManager::configDatabase('password');
if ($username != '<DBAUTH>' || $password != '<DBAUTH>') {
?>
    <div class="layout-row min-size">
        <div class="callout callout-warning">
            <div class="header">
                <i class="icon-warning"></i>
                <h3><?= e(trans('dbauth::lang.hints.real_user')) ?></h3>
                <p><?=  e(trans('dbauth::lang.hints.edit_env')) ?></p>
            </div>
        </div>
    </div>
<?php } ?>