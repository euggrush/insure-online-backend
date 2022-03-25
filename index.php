<?php

require_once 'core.php';

$app = new CarInsurance\App();

$urlPart = "";

// url before ?
if ( preg_match( '~^([^\?]+)(?:\?|$)~iu', $app->uri, $matches ) ) {
  $urlPart = $matches[1];
}

$model = null;

if ( $urlPart === '/' ) {
  $model = CarInsurance\Template::pageFromHTML( file_get_contents( __DIR__ . '/entrypoint.html' ) );
}
else if ( CarInsurance\Utils::startsWith( $urlPart, '/api/' ) ) {
  $app->query = $app->db->escape( urldecode( trim( $matches[1] ) ) );   
  $model = new CarInsurance\Api( $app );
}

else {
  CarInsurance\Template::error( $app->lang['module_not_found'], 1 );
}
