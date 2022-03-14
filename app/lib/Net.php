<?php

use CarInsurance\Settings as Settings;

class Net {
	public static function httpConcurrentRequests( $requests = [ 
		'url' => '',
		'postdata' => null,
		'headers' => null,
		'view_headers' => false,
		'proxy' => null,
		'mobile' => false,
		'use_cookies_storage' => false,
		'use_ipv6' => false,
		'extra' => null,
	]) : array {
	
		if ( !is_array( $requests ) || !count( $requests ) || empty( $requests[0]['url'] ) ) {
			throw new InvalidArgumentException( "Bad requests parameter." );
		}
	
		$data = [];
		$mh = curl_multi_init();
		$channels = [];
		
		foreach( $requests as $request ) {
			if ( !empty( $request['use_cookies_storage'] ) && $request['use_cookies_storage'] ) {
				$cookieDir = __DIR__ . '/';
				$cookieFile = 'cookies';
	
				if ( !file_exists( $cookieDir ) ) {
					@mkdir( $cookieDir, 0777, true );
				}
			}

			if ( empty( $request['proxy'] ) ) {
				if ( empty( $request['use_ipv6'] ) ) {
					$ip4count = count( Settings::IP4_INTERFACES );
				
					if ( $ip4count > 0 )
						$interface = Settings::IP4_INTERFACES[ random_int( 0, $ip4count - 1 ) ];
					else
						$interface = "";
					
					$curl_resolve = CURL_IPRESOLVE_V4;
				}
				else {
					$ips6 = @file( "/usr/share/iplist/ip6.txt", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES );

					if ( $ips6 && count( $ips6 ) > 0 ) {
						$ips6count = count( $ips6 );
						$interface = $ips6[ random_int( 0, $ips6count - 1 ) ];
						$interface = str_replace( '/64', '', $interface );
						$curl_resolve = CURL_IPRESOLVE_V6;
					}
					else {
						$ip4count = count( Settings::IP4_INTERFACES );
				
						if ( $ip4count > 0 )
							$interface = Settings::IP4_INTERFACES[ random_int( 0, $ip4count - 1 ) ];
						else
							$interface = "";
						
						$curl_resolve = CURL_IPRESOLVE_V4;
					}
				}
			}
			else {
				$interface = "";
				$curl_resolve = CURL_IPRESOLVE_V4;
			}


			$ch = curl_init();
	
			$send = [];
	
			if ( !empty( $request['headers'] ) && is_array( $request['headers'] ) ) {
				$send = array_merge( $send, $request['headers'] );
			}
			
			if ( isset( $request['postdata'] ) ) {
				curl_setopt($ch, CURLOPT_POST, 1);
				curl_setopt($ch, CURLOPT_POSTFIELDS, $request['postdata']);
			}
			
			curl_setopt($ch, CURLOPT_URL, $request['url'] );
			
			if ( empty( $request['view_headers'] ) ) {
				curl_setopt($ch, CURLOPT_HEADER, 0);
				curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
			}
			else {
				curl_setopt($ch, CURLOPT_HEADER, 1);
				curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0);
			}
			
			if ( !empty( $request['proxy'] ) && is_string( $request['proxy'] ) ) {
				curl_setopt( $ch, CURLOPT_PROXY, $request['proxy'] );
			}
			else if ( !empty( $request['proxy'] ) && is_array( $request['proxy'] ) ) {
				if ( !empty( $request['proxy']['ip_port'] ) ) curl_setopt( $ch, CURLOPT_PROXY, $request['proxy']['ip_port'] );
				if ( !empty( $request['proxy']['proxytype'] ) ) curl_setopt( $ch, CURLOPT_PROXYTYPE, $request['proxy']['proxytype'] );
				if ( !empty( $request['proxy']['proxyuserpwd'] ) ) curl_setopt( $ch, CURLOPT_PROXYUSERPWD, $request['proxy']['proxyuserpwd'] );
			}
			
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
			
			if ( !empty($request['proxy']) ) {
				curl_setopt($ch, CURLOPT_TIMEOUT, 10);
			}
			else {
				curl_setopt($ch, CURLOPT_TIMEOUT, 5);
			}
	
			curl_setopt($ch, CURLOPT_NOBODY, 0);
			curl_setopt($ch, CURLOPT_HTTPHEADER, $send);

			if ( empty( $request['proxy'] ) && mb_strlen( $interface ) > 0 )
				curl_setopt($ch, CURLOPT_INTERFACE, $interface);

			if ( !empty( $request['use_cookies_storage'] ) && $request['use_cookies_storage'] ) {
				curl_setopt($ch, CURLOPT_COOKIEJAR, $cookieDir . $cookieFile );
				curl_setopt($ch, CURLOPT_COOKIEFILE, $cookieDir . $cookieFile );
			}

			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
			curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
			curl_setopt($ch, CURLOPT_VERBOSE, false);
			curl_setopt($ch, CURLOPT_IPRESOLVE, $curl_resolve);
			
			curl_multi_add_handle($mh, $ch);
			
			$channels[] = $ch;
		}
		
		$active = null;
		do {
			$mrc = curl_multi_exec($mh, $active);
		} while ($mrc == CURLM_CALL_MULTI_PERFORM);
		 
		while ($active && $mrc == CURLM_OK) {
			if (curl_multi_select($mh) == -1) {
				usleep(1);
				continue;
			}
	
			do {
				$mrc = curl_multi_exec($mh, $active);
			} while ($mrc == CURLM_CALL_MULTI_PERFORM);
		}
		 
		foreach ($channels as $i => $channel) {
			$data[ $i ]['data'] = curl_multi_getcontent($channel);
			$data[ $i ]['info'] = curl_getinfo( $channel );
			$data[ $i ]['extra'] = $requests[ $i ]['extra'] ?? null;
			curl_multi_remove_handle($mh, $channel);
		}
		
		//var_dump(curl_multi_errno($mh));
		 
		curl_multi_close($mh);
	
		return $data;
	}

  public static function httpRequest( $url='', $options = [ 
		'postdata' => null,
		'headers' => null,
		'view_headers' => false,
		'proxy' => null,
		'mobile' => false,
		'use_cookies_storage' => false,
		'use_ipv6' => false
	]) : array {
		
		if ( !empty( $options['use_cookies_storage'] ) && $options['use_cookies_storage'] ) {
			$cookieDir = __DIR__ . '/';
			$cookieFile = 'cookies';

			if ( !file_exists( $cookieDir ) ) {
				@mkdir( $cookieDir, 0777, true );
			}
		}
		
		if ( empty( $options['proxy'] ) ) {
			if ( empty( $options['use_ipv6'] ) ) {
				$ip4count = count( Settings::IP4_INTERFACES );

				if ( $ip4count > 0 )
					$interface = Settings::IP4_INTERFACES[ random_int( 0, $ip4count - 1 ) ];
				else
					$interface = "";
				
				$curl_resolve = CURL_IPRESOLVE_V4;
			}
			else {
				$ips6 = @file( "/usr/share/iplist/ip6.txt", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES );

				if ( $ips6 && count( $ips6 ) > 0 ) {
					$ips6count = count( $ips6 );
					$interface = $ips6[ random_int( 0, $ips6count - 1 ) ];
					$interface = str_replace( '/64', '', $interface );
					$curl_resolve = CURL_IPRESOLVE_V6;
				}
				else {
					$ip4count = count( Settings::IP4_INTERFACES );
				
					if ( $ip4count > 0 )
						$interface = Settings::IP4_INTERFACES[ random_int( 0, $ip4count - 1 ) ];
					else
						$interface = "";
						
					$curl_resolve = CURL_IPRESOLVE_V4;
				}
			}
		}
		else {
			$interface = "";
			$curl_resolve = CURL_IPRESOLVE_V4;
		}
		
		$send = array();
		
		if ( !empty( $options['mobile'] ) && $options['mobile'] ) {
			//$send[] = "User-Agent: Mozilla/5.0 (Linux; Android 9; SAMSUNG SM-A600FN) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/10.1 Chrome/71.0.3578.99 Mobile Safari/537.36";
		}
		else {
			//$send[] = "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36";
		}
		
		if ( !empty( $options['headers'] ) && is_array( $options['headers'] ) ) {
			$send = array_merge( $send, $options['headers'] );
		}
			
		$ch = curl_init();
		
		if ( isset( $options['postdata'] ) ) {
			curl_setopt($ch, CURLOPT_POST, 1);
			curl_setopt($ch, CURLOPT_POSTFIELDS, $options['postdata']);
		}
		
		curl_setopt( $ch, CURLOPT_URL, $url );
		
		if ( !empty( $options['view_headers'] ) && $options['view_headers'] ) {
			curl_setopt($ch, CURLOPT_HEADER, 1);
			curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0);
		}
		else {
			curl_setopt($ch, CURLOPT_HEADER, 0);
			curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
		}
		
		if ( !empty( $options['proxy'] ) && is_string( $options['proxy'] ) ) {
			curl_setopt( $ch, CURLOPT_PROXY, $options['proxy'] );
		}
		else if ( !empty( $options['proxy'] ) && is_array( $options['proxy'] ) ) {
			if ( !empty( $options['proxy']['ip_port'] ) ) curl_setopt( $ch, CURLOPT_PROXY, $options['proxy']['ip_port'] );
			if ( !empty( $options['proxy']['proxytype'] ) ) curl_setopt( $ch, CURLOPT_PROXYTYPE, $options['proxy']['proxytype'] );
			if ( !empty( $options['proxy']['proxyuserpwd'] ) ) curl_setopt( $ch, CURLOPT_PROXYUSERPWD, $options['proxy']['proxyuserpwd'] );
		}
		
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		
		if ( !empty( $options['proxy'] ) ) {
			curl_setopt($ch, CURLOPT_TIMEOUT, 10);
		}
		else {
			curl_setopt($ch, CURLOPT_TIMEOUT, 5);
		}
	
		curl_setopt($ch, CURLOPT_NOBODY, 0);
		curl_setopt($ch, CURLOPT_HTTPHEADER, $send);

		if ( empty( $request['proxy'] ) && mb_strlen( $interface ) > 0 )
				curl_setopt($ch, CURLOPT_INTERFACE, $interface);

		if ( !empty( $options['use_cookies_storage'] ) && $options['use_cookies_storage'] ) {
			curl_setopt($ch, CURLOPT_COOKIEJAR, $cookieDir . $cookieFile );
			curl_setopt($ch, CURLOPT_COOKIEFILE, $cookieDir . $cookieFile );
		}

		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
		curl_setopt($ch, CURLOPT_VERBOSE, false);
		curl_setopt($ch, CURLOPT_IPRESOLVE, $curl_resolve);
			
		$data = curl_exec($ch);
		
		$info = curl_getinfo( $ch );
		
		if ( !mb_strlen( $data ) ) {
			$info['curl_errno'] = curl_errno($ch);
			$info['curl_error'] = curl_error($ch);
			$info['curl_errstr'] = "Curl error : {$info['curl_error']}({$info['curl_errno']}). ";
		}
		else {
			$info['curl_errno'] = 0;
			$info['curl_error'] = "";
			$info['curl_errstr'] = "";
		}
			
		curl_close($ch);
		
		return array( 'data' => $data, 'info' => $info );
	}

	public static function net_match( $network , $ip ) {
		if(strpos($network,'/') === FALSE ){
			return $network == $ip;
		}
	
		$ip_arr = explode ( '/' , $network );
		$network_long = ip2long ( $ip_arr [ 0 ]);
	
		$x = ip2long ( $ip_arr [ 1 ]);
		$mask = long2ip ( $x ) == $ip_arr [ 1 ] ? $x : 0xffffffff << ( 32 - $ip_arr [ 1 ]);
		$ip_long = ip2long ( $ip );
	
		return ( $ip_long & $mask ) == ( $network_long & $mask );
	}
}