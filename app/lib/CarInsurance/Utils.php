<?php

namespace CarInsurance;

final class Utils {
    public static function time_to_iso8601( $t=0 ) {
		$t = date( "Y-m-d H:i:s", $t );
		$datetime = new \DateTime( $t );
		return $datetime->format(\DateTime::ISO8601);
	}

	public static function time_to_iso8601_duration( $time=0 ) {
		$units = array(
			"Y" => 365*24*3600,
			"D" =>     24*3600,
			"H" =>        3600,
			"M" =>          60,
			"S" =>           1,
		);

		$str = "P";
		$istime = false;

		foreach ($units as $unitName => &$unit) {
			$quot  = intval($time / $unit);
			$time -= $quot * $unit;
			$unit  = $quot;
			if ($unit > 0) {
				if (!$istime && in_array($unitName, array("H", "M", "S"))) { // There may be a better way to do this
					$str .= "T";
					$istime = true;
				}
				$str .= strval($unit) . $unitName;
			}
		}

		return $str;
	}

	public static function format_time( $t=0, $f=':', $hours=false ) {
		if ( $hours ) { return sprintf("%02d%s%02d%s%02d", floor($t/3600), $f, ($t/60)%60, $f, $t%60); }
		else { return sprintf("%02d%s%02d", $t/60, $f, $t%60); }
	}
	
	public static function filter_string( $q="", $mode='query' ) {
		$q = htmlspecialchars_decode( $q, ENT_QUOTES );

		while ( strpos( $q, '  ' ) !== false ) {
			$q = str_replace( '  ', ' ', $q );
		}

		$filterMasks = [ '#', "'", '<', '>', '&', '"', '--', '\\', '/', ')', '(', 
			']', '[', '}', '{', '@', '.', ',', '*', '+', '~', '?', '!' ];

		if ( $mode == 'tag' ) {
			$filterMasks[] = ' ';
		}

		$q = str_replace( $filterMasks, '', $q );
		$q = preg_replace( '~^\-(.+)~iu', '$1', $q );
	
		//$q = mb_strtolower( $q );
		$q = trim( $q );
		$q = mb_substr( $q, 0, 1000 );
		
		return $q;
	}
	
	public static function startsWith($haystack, $needle) {
		$length = mb_strlen($needle);
		return (mb_substr($haystack, 0, $length) === $needle);
	}
	
	public static function endsWith($haystack, $needle) {
		$length = mb_strlen($needle);
	
		return $length === 0 || 
		(mb_substr($haystack, -$length) === $needle);
	}
	
	public static function uSortByLength($a,$b){
		return mb_strlen($b)-mb_strlen($a);
	}

	public static function crop( $url, $width = 0, $height = 0 ) {
		$imageData = @getimagesize($url);
	  
		if ( !$imageData || !is_array( $imageData ) || count( $imageData ) < 3 ) {
			header( "{$_SERVER['SERVER_PROTOCOL']} 404" );
			exit("Bad image");
		}
	  
		[ $origWidth, $origHeight, $type ] = $imageData;
	  
	  
		if ($width == 0) {
			$width  = $origWidth;
		}
	  
		if ($height == 0) {
			$height = $origHeight;
		}
	  
		// Calculate ratio of desired maximum sizes and original sizes.
		$widthRatio = $width / $origWidth;
		$heightRatio = $height / $origHeight;
	  
		// Ratio used for calculating new image dimensions.
		$ratio = min($widthRatio, $heightRatio);
	  
		// Calculate new image dimensions.
		$newWidth  = (int)$origWidth  * $ratio;
		$newHeight = (int)$origHeight * $ratio;
	  
		// Create final image with new dimensions.
		$newImage = @imagecreatetruecolor($newWidth, $newHeight);

		if ( $type === IMAGETYPE_GIF )
			$image = @imagecreatefromgif($url);
		else if ( $type === IMAGETYPE_JPEG )
			$image = @imagecreatefromjpeg($url);
		else if ( $type === IMAGETYPE_PNG )
			$image = @imagecreatefrompng($url);
		
		imagecopyresampled($newImage, $image, 0, 0, 0, 0, $newWidth, $newHeight, $origWidth, $origHeight);
	  
		if ( $newImage ) {
			header( "Content-type: image/jpeg" );
			imagejpeg($newImage);
			imagedestroy($newImage);
		}
		else {
			header( "{$_SERVER['SERVER_PROTOCOL']} 404" );
			exit("Bad image");
		}
	}

	public static function telegram( $params = [] ) {
		//return;
		$params['message'] = mb_substr( $params['message'], 0, 1200, 'UTF-8' );
		$message = urlencode( $params['message'] );
	
		$url = "https://api.telegram.org/bot{$params['bot_id']}:{$params['bot_token']}/sendMessage?chat_id={$params['chat_id']}&text={$message}";
	
		$curl = curl_init($url);
		curl_setopt($curl, CURLOPT_HEADER, false);
		curl_setopt($curl, CURLOPT_VERBOSE, false);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($curl, CURLOPT_AUTOREFERER, true); 
	
		$output = curl_exec($curl);
	
		curl_close($curl);
	}

	public static function generateId( $length = 12 ) {
		// 65-90 big letters
		// 95 underscore
		// 97-122 small letters
		// 48-57 digits

		$id = '';
		$set = array();

		for( $i = 65; $i <= 90; ++$i ) {
			$set[] = chr( $i );
		}

		$set[] = chr( 95 );

		for( $i = 97; $i <= 122; ++$i ) {
			$set[] = chr( $i );
		}

		for( $i = 48; $i <= 57; ++$i ) {
			$set[] = chr( $i );
		}

		while( strlen( $id ) < $length ) {
			$id .= $set[ mt_rand(0, 62) ];
		}

		return $id;
	}

	public static function generateUUID4() {
		return sprintf( '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
			// 32 bits for "time_low"
			mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ),
	
			// 16 bits for "time_mid"
			mt_rand( 0, 0xffff ),
	
			// 16 bits for "time_hi_and_version",
			// four most significant bits holds version number 4
			mt_rand( 0, 0x0fff ) | 0x4000,
	
			// 16 bits, 8 bits for "clk_seq_hi_res",
			// 8 bits for "clk_seq_low",
			// two most significant bits holds zero and one for variant DCE1.1
			mt_rand( 0, 0x3fff ) | 0x8000,
	
			// 48 bits for "node"
			mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff )
		);
	}

	function remove_emoji($string) {
		// Match Enclosed Alphanumeric Supplement
		$regex_alphanumeric = '/[\x{1F100}-\x{1F1FF}]/u';
		$clear_string = preg_replace($regex_alphanumeric, '', $string);

		// Match Miscellaneous Symbols and Pictographs
		$regex_symbols = '/[\x{1F300}-\x{1F5FF}]/u';
		$clear_string = preg_replace($regex_symbols, '', $clear_string);

		// Match Emoticons
		$regex_emoticons = '/[\x{1F600}-\x{1F64F}]/u';
		$clear_string = preg_replace($regex_emoticons, '', $clear_string);

		// Match Transport And Map Symbols
		$regex_transport = '/[\x{1F680}-\x{1F6FF}]/u';
		$clear_string = preg_replace($regex_transport, '', $clear_string);
		
		// Match Supplemental Symbols and Pictographs
		$regex_supplemental = '/[\x{1F900}-\x{1F9FF}]/u';
		$clear_string = preg_replace($regex_supplemental, '', $clear_string);

		// Match Miscellaneous Symbols
		$regex_misc = '/[\x{2600}-\x{26FF}]/u';
		$clear_string = preg_replace($regex_misc, '', $clear_string);

		// Match Dingbats
		$regex_dingbats = '/[\x{2700}-\x{27BF}]/u';
		$clear_string = preg_replace($regex_dingbats, '', $clear_string);

		return $clear_string;
	}

	public static function mb_ucfirst($str='') {
		$fc = mb_strtoupper(mb_substr($str, 0, 1));
		return $fc.mb_substr($str, 1);
	}
	
	public static function cut_domain( $t="" )
	{
		return preg_replace( "/(^|\s*)\S{2,}?\.\S{2,}?(\s|$)/imu", "$1$2", $t );
	}

	public static function cut_url( $t="" )
	{
		return preg_replace( "~(^|\s*)https?://.+?(\s|$)~imu", "$1$2", $t );
	}

	public static function saveFile( $from, $to ) {
		if ( !file_exists( $to ) ) {
			$binData = @file_get_contents( $from, false, stream_context_create([
				'http' => [
					'timeout' => 10,
					'follow_location' => 1,
				],
				'ssl' => [
					"verify_peer" => false,
					"verify_peer_name" => false,
				],
			]) );
	
			$filePath = mb_strrichr( $to, '/', true );
	
			if ( !file_exists( $filePath ) ) {
				@mkdir( $filePath, 0777, true );
			}
	
			if ( strlen( $binData ) > 0 )
				return boolval( @file_put_contents( $to, $binData, LOCK_EX ) );
			else 
				return false;
		}
		return true;
	}

	public static function saveFileData( $binData, $to ) {
		if ( !file_exists( $to ) ) {
			$filePath = mb_strrichr( $to, '/', true );
	
			if ( !file_exists( $filePath ) ) {
				@mkdir( $filePath, 0777, true );
			}
	
			if ( strlen( $binData ) > 0 )
				return boolval( @file_put_contents( $to, $binData, LOCK_EX ) );
			else 
				return false;
		}
		return true;
	}

	public static function random($length = 16) {
        $string = '';

        while (($len = strlen($string)) < $length) {
            $size = $length - $len;

            $bytes = random_bytes($size);

            $string .= substr(str_replace(['/', '+', '='], '', base64_encode($bytes)), 0, $size);
        }

        return $string;
	}

	public static function agosec($inputSeconds) {
		$all = time() - $inputSeconds;

		$then = new \DateTime(date('Y-m-d H:i:s', $inputSeconds));
		$now = new \DateTime(date('Y-m-d H:i:s', time()));
		$diff = $then->diff($now);
		return array('all' => $all, 'years' => $diff->y, 'months' => $diff->m, 'days' => $diff->d, 'hours' => $diff->h, 'minutes' => $diff->i, 'seconds' => $diff->s);
	}

	public static function pagination( $total, $active, $perpage, $uri ) {

		$total = intval( $total ); 
		$active = intval( $active ); 
		$perpage = intval( $perpage ); 
		$pages = ceil( $total / $perpage );

		if ( $total <= $perpage ) return "";
	
		$start = $active - 2;
		$finish = $active + 3;
	
		if ( $start < 0 ) $start = 0;
		if ( $finish < 5 ) $finish = 5;
		if ( $finish > $pages ) $finish = $pages;
	
		if ( $active === 0 ) {
			$tpl = 'pagination-disabled-prev';
		}
		else if ( $active >= ( $pages - 1 ) ) {
			$tpl = 'pagination-disabled-next';
		}
		else {
			$tpl = 'pagination';
		}
	
		$pages_html = [];
	
		for ( $i = $start; $i < $finish; ++$i ) {
			if ( $i === $active ) 
				$currentPage = 'pagination-page-active';
			else
				$currentPage = 'pagination-page-link';

			$currentPage = Template::getFragment( $currentPage );

			$currentPage = str_replace( '{href}', $uri . $i, $currentPage );
			$currentPage = str_replace( '{num}', strval( $i + 1 ), $currentPage );

			$pages_html[] = $currentPage;
	
		}

		$tpl = Template::getFragment( $tpl );
		$tpl = str_replace( '{pages}', implode( "", $pages_html ), $tpl );
	
		return $tpl;
	}

	public static function pagination2( $total, $active, $perpage, $uri ) { // 1 2 3 ... 10

		$total = intval( $total ); 
		$active = intval( $active ); 
		$perpage = intval( $perpage ); 
		$return = null;
		$pages = ceil( $total / $perpage );

		$start = 0;
		$finish = $pages;

		$return = "\t\t\t\t\t\t<div class='site-pagination'>\n";

		for ( $i = $start; $i < $finish; $i++ )
		{
			$displayed = $i + 1;
			$currentUri = $uri;
		
			if ( ( $finish - $i >= 4 ) && ( $i - $start > 2 ) && ( $i != $active ) && ( ($i - $active >= 3) || ($active - $i >= 3) ) )
			{
				$return .= "...";
				$return = str_replace("......", "...", $return);
			}
			else
			{
				if ( $i != $active )
				{
					if ( $i > 0 ) {
						$return .= "\t\t\t\t\t\t\t<a id='page{$i}' href='{$currentUri}{$i}' class='pl-3 pr-3'>{$displayed}</a>\n";
					}
					else {
						if ( mb_strlen( $currentUri ) > 1 && Utils::endsWith( $currentUri, '/' ) ) {
							$currentUri = mb_substr( $currentUri, 0, -1 );
						}
						else if ( mb_strlen( $currentUri ) > 1 && Utils::endsWith( mb_strtolower( $currentUri ), '&page=' ) ) {
							$currentUri = str_ireplace( '&page=', '', $currentUri );
						}

						$return .= "\t\t\t\t\t\t\t<a id='page{$i}' href='{$currentUri}' class='pl-3 pr-3'>{$displayed}</a>\n";
					}
				}
				else
				{
					$return .= "\t\t\t\t\t\t\t<a id='page{$i}' class='current pl-3 pr-3' href='#'>{$displayed}</a>\n";

				}
			}

		}
		
		$return = str_replace("...", "\t\t\t\t\t\t\t<span class='pl-3 pr-3'>...</span>\n", $return);
	
		$return .= "\n\t\t\t\t\t\t</div>";

		return $return;
	
	}
}