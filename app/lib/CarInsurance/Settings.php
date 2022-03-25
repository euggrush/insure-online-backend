<?php

namespace CarInsurance;

class Settings {
  
  protected $dbSettings = [
    'dbhost' => 'localhost',
    'dbuser' => '',
    'dbpass' => '',
    'dbname' => '',
    'dbcharset' => 'utf8mb4'
  ];

  protected string $default_title = '';
  protected string $default_description = '';
  protected string $default_keywords = '';

  public const SECRET = '';
  public const DEFAULT_ENCRYPT_ALGORITHM = "AES-256-CBC";
  public const DEFAULT_SECRET_KEY = '';
  public const DEFAULT_IV = '';

  public const ACCESS_TOKEN_HASH_SECRET = '';
  
  public const IP4_INTERFACES = [
    
  ];
  public const IP4_PROXIES = [
    
  ];

  public const DBNAME = '';

  public const AUTH_ATTEMPTS = 1000;
  public const AUTH_ATTEMPTS_INTERVAL = "PT30M";
  public const TOKEN_EXPIRATION_INTERVAL = "PT6H";

  public const MAX_ESTIMATIONS_PER_ORDER = 5;

  public const UPLOAD_INTERVAL = "PT24H";
  public const MAX_UPLOADS_PER_UPLOAD_INTERVAL = 50;
  public const MAX_UPLOADS_PER_ONCE = 10;
  public const UPLOAD_MAX_FILESIZE = 5_120_000;

  public const PAGINATION_MAX_LIMIT = 100;

  public const PASSWORD_HASH_ALGO = PASSWORD_DEFAULT;

  public const FROM_EMAIL = '';
  public const FROM_NAME = '';

  public const MAIL = [
    'Host'     => '',
    'SMTPAuth'   => true,
    'Username'   => '',
    'Password'   => '',
    'SMTPSecure' => 'tls',
    'Port'     => 587,
  ];
}