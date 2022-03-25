<?php

# mysqli driver v3.1 ( compatible with php8.0 ) - 2022-01-20

class Database extends \mysqli {

  // log folder path
  private string $mysqlLogsDir;

  // throws Exception or return false
  private bool $throwExceptionOnError = true;

  // extra vars
  private array $vars = [];

  public function setVar( string $key, mixed $value ) : void {
    $this->vars[ $key ] = $value;
  }

  public function getVar( string $key ) : mixed {
    try {
      return $this->vars[ $key ];
    }
    catch( ErrorException ) {
      return null;
    }
  }

  public function getAllVars() : array {
    return $this->vars;
  }

  public function clearVars() : void {
    $this->vars = [];
  }

  public function getThrowExceptionOnErrorState() : bool {
    return $this->throwExceptionOnError;
  }

  public function setThrowExceptionOnErrorState( bool $value ) : void {
    $this->throwExceptionOnError = $value;
  }

  public function __construct( array $c ) {
    @parent::__construct( $c['dbhost'], $c['dbuser'], $c['dbpass'], $c['dbname'], $c['dbport'] ?? 3306 );

    if ($this->connect_error) {
      $failtext = 'Connection error (' . $this->connect_errno . ') ' . $this->connect_error;
          
      $this->writeErrorLog( $failtext, 1 );
      
      if ( !$this->throwExceptionOnError ) {
        return false;
      }
      else {
        throw new \Exception( "Database connection error.", 100 );
      }
    }
    
    $c['dbcharset'] = isset( $c['dbcharset'] ) ? $c['dbcharset'] : 'utf8mb4';
    
    if (!parent::set_charset($c['dbcharset'])) {
      $failtext = "{$c['dbcharset']} charset error";

      $this->writeErrorLog( $failtext, 1 );
      
      if ( !$this->throwExceptionOnError ) {
        return false;
      }
      else {
        throw new \Exception( "Database connection error.", 101 );
      }
    }

    return true;
  }
  
  // @Override
  public function query( string $sql, int $behavior = MYSQLI_STORE_RESULT ) : mysqli_result|bool {  
    $q1 = parent::query( $sql, $behavior );
    
    if ( $q1 === false ) {
      $this->writeErrorLog( '"' . $sql . '" -> ' . $this->error, 2 );
      
      if ( !$this->throwExceptionOnError ) {
        return null;
      }
      else {
        throw new \Exception( "Database query error.", 102 );
      }
    }
    else return $q1;
  }

  public function getSQLLine( array $data = [] ) : string {
    $sqlPairs = [];

    foreach( $data as $key => $value ) {
      $key = $this->clean( $key );

      if ( is_null( $value ) ) {
        $sqlPairs[] = "{$key} = NULL";
      }
      else if ( is_bool( $value ) ) {
        $sqlPairs[] = "{$key} = \"" . intval( $value ) . "\"";
      }
      else if ( is_int( $value ) ) {
        $value = intval( $value );
        $sqlPairs[] = "{$key} = {$value}";
      }
      else if ( is_float( $value ) ) {
        $value = floatval( $value );
        $sqlPairs[] = "{$key} = {$value}";
      }
      else if ( is_object( $value ) || is_array( $value ) ) {
        $value = json_encode( $value, JSON_UNESCAPED_UNICODE );
        $value = $this->clean( $value );
        $sqlPairs[] = "{$key} = \"{$value}\"";
      }
      else {
          $value = $this->clean( $value );
          $sqlPairs[] = "{$key} = \"{$value}\"";
      }
    }

    if ( count( $sqlPairs ) > 0 ) return implode( ", ", $sqlPairs );
    else return "";
  }
  
  public function writeErrorLog( string $msg, int $type = 1 ) : void {
    $trace = debug_backtrace();
    $file = $trace[0]['file'];
    $line = $trace[0]['line'];

    $message = gmdate( 'd M y H:i:s', time() ) . " UTC in " . $file . "(" . $line . "): {$msg}" . PHP_EOL . PHP_EOL;

    $this->mysqlLogsDir = __DIR__ . '/logs/mysql/' . mktime(0, 0, 0);
    
    if ( !file_exists( $this->mysqlLogsDir ) ) {
      @mkdir( $this->mysqlLogsDir, 0777, true );
      @chmod( $this->mysqlLogsDir, 0777 );
    }
    
    if ( $type == 1 ) { $fname = $this->mysqlLogsDir . '/mysql_connect_errors.txt'; }
    else if ( $type == 2 ) { $fname = $this->mysqlLogsDir . '/mysql_query_errors.txt'; }
    else { $fname = $this->mysqlLogsDir . '/mysql_all_errors.txt'; }
    
    file_put_contents( $fname, $message, FILE_APPEND | LOCK_EX );
  }
  
  public function clean( $a ) : string {
    return $this->real_escape_string( $a );
  }

  public function escape( $a ) : string {
    return $this->real_escape_string( $a );
  }
  
  public function __destruct() {
    @parent::close();
  }
}
