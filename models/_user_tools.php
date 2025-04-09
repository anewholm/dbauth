<div class="form-group switch-field span-left" id="Form-field-User-acorn_create_user-group">
    <div class="field-switch">
        <label for="Form-field-User-acorn_create_user">Create and synchronise DB user</label>
        <p class="help-block">This includes password changes.</p>
    </div>

    <input type="hidden" name="acorn_create_user" value="0">

    <label class="custom-switch">
        <input type="checkbox" checked="1" id="Form-field-User-acorn_create_user" name="acorn_create_user" value="1">
        <span><span>On</span><span>Off</span></span>
        <a class="slide-button"></a>
    </label>
</div>

<div class="form-group  widget-field span-right" id="Form-field-User-password-group">
    <label for="Form-field-User-password">
        Password            
    </label>
    <div data-control="sensitive" data-clean="true" data-hide-on-tab-change="true" data-disposable="">
        <div class="loading-indicator-container size-form-field">
            <div class="input-group">
                <input type="password" name="dbauth_password" id="Sensitive-formDBAuth-password" value="" placeholder="" class="form-control" autocomplete="off" data-input="">
                            <a href="javascript:;" class="input-group-addon btn btn-secondary" data-toggle="">
                    <i class="icon-eye" data-icon=""></i>
                </a>
            </div>
            <div class="loading-indicator hide" data-loader="">
                <span class="p-a"></span>
            </div>
        </div>
    </div>
</div>

<div class="form-group checkbox-field" style="clear:both" id="Form-field-User-acorn_rolecreate-group">
    <div class="checkbox custom-checkbox" tabindex="0">
        <input type="hidden" name="acorn_rolecreate" value="0">
        <input type="checkbox" id="Form-field-User-acorn_rolecreate" name="acorn_rolecreate" value="1" checked="checked">
        <label for="Form-field-User-acorn_rolecreate">Allow user to create session sub-role: token_<?= $model->id ?></label>
        <p class="help-block">This sub-role is used for general Database sessions after initial login with the main role.</p>
    </div>
</div>

<div class="form-group checkbox-field" style="clear:both" id="Form-field-User-acorn_withgrantoption-group">
    <div class="checkbox custom-checkbox" tabindex="0">
        <input type="hidden" name="acorn_withgrantoption" value="0">
        <input type="checkbox" id="Form-field-User-acorn_withgrantoption" name="acorn_withgrantoption" value="1" checked="checked">
        <label for="Form-field-User-acorn_withgrantoption">Allow user to grant privileges to its session sub-role: token_<?= $model->id ?></label>
        <p class="help-block">This sub-role is used for general Database sessions after initial login with the main role.</p>
    </div>
</div>

<!-- TODO: Enable / Disable this field according to is_superuser -->
<div class="form-group checkbox-field" id="Form-field-User-acorn_db_super_user-group">
    <div class="checkbox custom-checkbox" tabindex="0">
        <input type="hidden" name="acorn_db_super_user" value="0">
        <input type="checkbox" id="Form-field-User-acorn_db_super_user" name="acorn_db_super_user" value="1" checked="checked">
        <label for="Form-field-User-acorn_db_super_user">Make DB super-user <?= ($model->is_superuser ? 'AVAILABLE' : 'UNAVAILABLE') ?></label>
        <p class="help-block">This will only be available if the user is marked as a super user in Winter above.</p>
    </div>
</div>
