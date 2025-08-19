<?php 
$model    = (isset($formModel) ? $formModel : $record);
$config   = (isset($formField) ? $formField->config : $column->config);
$cssClass = (isset($config['cssClass']) ? $config['cssClass'] : '');
$tick     = (isset($config['tick'])  ? $config['tick']  : '✔');
$cross    = (isset($config['cross']) ? $config['cross'] : '✘');

if (!is_null($value)) {
    $class    = ($value ? 'tick' : 'cross');
    $glyph    = ($value ? $tick  : $cross);
    print("<div class='tick-div $cssClass type-$class'>$glyph</div>");
}