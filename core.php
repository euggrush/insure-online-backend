<?php

ini_set( 'display_errors', 'On' );
error_reporting( E_ALL );

mb_internal_encoding( 'UTF-8' );
date_default_timezone_set( 'UTC' );

spl_autoload_register(function ($class) {
  $class = preg_replace( '~[^a-z0-9_\\\]~i', '', $class );
  $class = str_replace( '\\', '/', $class );

  require_once( __DIR__ . '/app/lib/' . $class . '.php' );
});

function exception_error_handler($errno, $message, $file, $line) {
  if (!(error_reporting() & $errno)) {
    // $errno not int error_reporting
    return;
  }

  throw new \ErrorException($message, 0, $errno, $file, $line);
}

set_error_handler('exception_error_handler');
