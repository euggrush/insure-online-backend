<?php

use CarInsurance\Settings as Settings;

class Encryption {
	private $use_default_iv, $algo, $key;

	public function __construct( bool $use_default_iv=false, string $algo="", string $key="" ) {
		$this->use_default_iv = $use_default_iv;
		$this->algo = mb_strlen( $algo ) > 0 ? $algo : Settings::DEFAULT_ENCRYPT_ALGORITHM;
		$this->key = mb_strlen( $key ) > 0 ? $key : Settings::DEFAULT_SECRET_KEY;
	}
	
	/**
	 * @return array
	**/
	public function encrypt( string $string, string $iv=null ) : array {
		return $this->encrypt_decrypt( 'encrypt', $string, $iv );
	}

	/**
	 * @return string
	**/
	public function decrypt( array $r ) : string {
		return $this->encrypt_decrypt( 'decrypt', $r['encrypted'], $r['iv'] );
	}
	
	private function encrypt_decrypt( string $action, string $string, string $iv=null ) {
		if ( $this->use_default_iv && $action === 'encrypt' ) {
			$iv = Settings::DEFAULT_IV;
		}
		else {
			if ( !isset( $iv ) ) {
				$iv = random_bytes( 16 );
			}
		}

		// hash
		$key = hash('sha256', $this->key);

		if ( $action == 'encrypt' ) {
			// iv - encrypt method AES-256-CBC expects 16 bytes - else you will get a warning
			$iv = substr(hash('sha256', $iv), 0, 16);

			$encrypted = openssl_encrypt( $string, $this->algo, $key, 0, $iv );
			return array( 'iv' => $iv, 'encrypted' => bin2hex( $encrypted ) );
		} else if ( $action == 'decrypt' ) {
			return openssl_decrypt( hex2bin( $string ), $this->algo, $key, 0, $iv );
		}
		else return null;
	}
}
