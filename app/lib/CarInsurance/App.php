<?php

namespace CarInsurance;

class App extends Settings {
  public string $from_cli, $http_scheme, $http_host, $http_protocol, $http_origin, $site, $ip_addr, $uri, $url, 
      $requestMethod, $canonical_link, $user_agent, $docDir, $xsrf;

  public ?string $sid;
  public int $timestamp, $start_time;
  public float $start_time_micro;
  public array $get, $post, $lang, $config, $headers;
  public ?array $user;
  public bool $url_rewrited, $isAjaxRequest;
  public \Database $db;

  public function __construct() {
    $this->from_cli = substr(php_sapi_name(), 0, 3) === 'cli';
    $this->http_scheme = isset( $_SERVER['HTTPS'] ) && $_SERVER['HTTPS'] == 'on' ? 'https' : 'http';
    $this->http_host = $_SERVER['HTTP_HOST'] ?? "";
    $this->http_protocol = $_SERVER['SERVER_PROTOCOL'] ?? "HTTP/1.1";
    $this->http_origin = $_SERVER['HTTP_ORIGIN'] ?? "*";
    $this->site = $this->http_scheme . '://' . $this->http_host;
    $this->timestamp = time();
    $this->start_time = $_SERVER['REQUEST_TIME'] ?? 0;
    $this->start_time_micro = $_SERVER['REQUEST_TIME_FLOAT'] ?? 0.0;
    $this->ip_addr = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? "";
    $this->geo_country = $_SERVER['HTTP_CF_IPCOUNTRY'] ?? "--";
    $this->uri = $_SERVER['REQUEST_URI'] ?? "";
    $this->url = $this->http_scheme . '://' . $this->http_host . $this->uri;
    $this->get = $_GET ?? [];
    $this->post = $_POST ?? [];
    $this->files = $_FILES ?? [];
    $this->requestMethod = $_SERVER['REQUEST_METHOD'] ?? "GET";
    $this->canonical_link = $this->url;
    $this->user_agent = $_SERVER['HTTP_USER_AGENT'] ?? "";
    $this->isAjaxRequest = $this->isAjaxRequest();
    $this->docDir = $_SERVER['DOCUMENT_ROOT'];
    $this->assetsDir = '/assets'; 

    $this->lang = ( new Language( 'en' ) )->lang;
    $this->db = new \Database( $this->dbSettings );
    
    if ( isset( $_SERVER['REDIRECT_URL'] ) ) {
      $this->url_rewrited = true;
    }
    else {
      $this->url_rewrited = false;
    }

    $this->user = null;
    
    $this->sid = isset( $_COOKIE['sid'] ) ? $this->db->clean( $_COOKIE['sid'] ) : null;
    
    if ( !$this->sid ) {
      $newCookieVal = md5( md5( microtime(true) ) . static::SECRET );
      setcookie( "sid", $newCookieVal, time()+86400*365, '/', ".{$this->http_host}" );
      $this->sid = $newCookieVal;
    }
    
    $this->xsrf = md5( md5( $this->sid ) . static::SECRET );

    $q0 = $this->db->query( "SELECT * FROM config" );

    while( $_config = $q0->fetch_assoc() ) {
      $this->config[ $_config['name'] ] = $_config['value'];
    }

    unset( $_config );
    $q0->free();

    $this->default_title = str_replace( '{host}', ucfirst( $this->http_host ), $this->default_title );
    
    $this->headers = [];
    
    $this->headers['host'] = &$this->http_host;
    $this->headers['year'] = date('Y');
    $this->headers['sitename'] = ucfirst( $this->headers['host'] );
    $this->headers['meta_title'] = $this->default_title;
    $this->headers['meta_description'] = $this->default_description;
    $this->headers['meta_keywords'] = $this->default_keywords;
    $this->headers['index_follow'] = 'index, follow';
    $this->headers['index_follow_gbot'] = 'index, follow';
    $this->headers['canonical'] = $this->canonical_link;

    Template::init( $this );
  }

  public function handleException( $e, $level=1 ) {
    $dt = new \DateTime( "now" );
    $etime = $dt->format( "Y-m-d H:i:s" );
    
    file_put_contents( __DIR__ . "/logs/secret_error_log", "Exception ({$etime}) at " . $e->getFile() . "(" . $e->getLine() . ")" . PHP_EOL . $e->getMessage() . PHP_EOL . $e->getTraceAsString() . PHP_EOL . PHP_EOL, LOCK_EX | FILE_APPEND );
    
    Template::error( "Internal error, please try again later.", 2 );
  }
  
  public function output( $content=[], $pure=false ) {
    if ( is_string( $content ) ) $content = [ "body" => $content ];
  
    Template::buildPage( $content, $pure );
    Template::sendHeaders();
    Template::displayPage();
  }

  private function isAjaxRequest() : bool {
    return ( ( isset( $_SERVER['HTTP_X_REQUESTED_WITH'] ) && $_SERVER['HTTP_X_REQUESTED_WITH'] == "XMLHttpRequest" ) || isset( $_SERVER['HTTP_ORIGIN'] ) );
  }
}
