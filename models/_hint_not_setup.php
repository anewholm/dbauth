<div class="layout-row min-size">
    <div class="callout callout-warning">
        <div class="header">
            <i class="icon-warning"></i>
            <h3><?= e(trans('Warning! Your .env contains a real username and password for the database. Please replace them with &quot;&lt;DBAUTH&gt;&quot; to enable this plugin.')) ?></h3>
            <p>
                <?= e(trans('Edit your .env file directly to enable security.')) ?>
            </p>
        </div>
    </div>
</div>
