<?php

require_once 'core.php';

$app = new CarInsurance\App();

$path = "";

// url before ?
if ( preg_match( '~^([^\?]+)(?:\?|$)~iu', $app->uri, $matches ) ) {
    $path = $matches[1];
}

$model = null;

if ( $path === '/' ) {
    $model = CarInsurance\Template::pageFromHTML( file_get_contents( __DIR__ . '/entrypoint.html' ) );
}
else if ( CarInsurance\Utils::startsWith( $path, '/api/' ) ) {
    $app->query = $app->db->escape( urldecode( trim( $path ) ) );   
    $model = new CarInsurance\Api( $app );
}

else {
    CarInsurance\Template::error( $app->lang['module_not_found'], 1 );
}
