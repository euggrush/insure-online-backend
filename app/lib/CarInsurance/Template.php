<?php

namespace CarInsurance;

class Template {
    private static App $app;
    private static ?string $tpl;

    public static function init( App &$app ) : void {
        if ( !isset( static::$app ) ) {
            static::$app = &$app;
        }
    }

    public static function error( string $text = "", $status = 1 ) : void {
        if ( !isset( static::$app ) ) {
            throw new \Exception( "You should run init( App ) before this." );
        }

        if ( !mb_strlen( $text ) ) {
            if ( $status === 1 )
				$text = "Module not found.";
			else if ( $status === 2 )
				$text = "Service temporarily unavailable, please try again later.";
			else if ( $status === 3 )
				$text = "Bad request.";
		}
		
		switch( $status ) {
			case 1:
				header( static::$app->http_protocol . " 404" );
			break;
			case 2:
				header( static::$app->http_protocol . " 503" );
			break;
			case 3:
				header( static::$app->http_protocol . " 400" );
			break;
        }
        
        if ( mb_strlen( $text ) > 0 )
            static::message( $text );
    }

    public static function message( string $text ) : void {
        if ( !isset( static::$app ) ) {
            throw new \Exception( "You should run init( App ) before this." );
        }

        $content = [];
        $content['body'] = file_get_contents( static::$app->docDir . '/app/tpl/message.tpl' );

        $content['body'] = str_replace( '{header}', 'Information', $content['body'] );
        $content['body'] = str_replace( '{text}', $text, $content['body'] );

        static::buildPage( $content );
		static::sendHeaders();
		static::displayPage();
    }

    public static function getFragment( string $fragment = "", array $options = [] ) : ?string {
        if ( !isset( static::$app ) ) {
            throw new \Exception( "You should run init( App ) before this." );
        }

        $body = file_get_contents( static::$app->docDir . '/app/tpl/' . $fragment . '.tpl' );

        foreach ( $options as $key => $value ) {
            $body = str_replace( '{' . $key . '}', $value, $body );
        }

        return $body;
    }

    public static function pageFromTEXT( string $text="" ) : void {
        $content = [];
        $content['body'] = $text;

        static::buildPage( $content );
		static::sendHeaders();
		static::displayPage();
    }

    public static function pageFromHTML( string $text="" ) : void {
        static::pageFromTEXT( $text );
    }

    public static function buildPage( $options = [], $pure = false ) : void {
        static::$tpl = null;

        if ( !isset( static::$app ) ) {
            throw new \Exception( "You should run init( App ) before this." );
        }

        if ( !$pure ) {
            $options['meta_title'] = $options['meta_title'] ?? static::$app->headers['meta_title'];
            $options['meta_description'] = $options['meta_description'] ?? static::$app->headers['meta_description'];
            $options['meta_keywords'] = $options['meta_keywords'] ?? static::$app->headers['meta_keywords'];
            $options['index_follow'] = $options['index_follow'] ?? static::$app->headers['index_follow'];
            $options['index_follow_gbot'] = $options['index_follow_gbot'] ?? static::$app->headers['index_follow_gbot'];
        
            $data = file_get_contents( static::$app->docDir . '/app/tpl/main.tpl' );
        
            foreach ( $options as $key => $value ) {
                $data = str_replace( '{' . $key . '}', $value, $data );
            }

            foreach ( static::$app->headers as $key => $value ) {
                $data = str_replace( '{' . $key . '}', $value, $data );
            }

            foreach ( static::$app->lang as $key => $value ) {
                $data = str_replace( '{lang:' . $key . '}', $value, $data );
            }
        
            static::$tpl = $data;
        }
        else static::$tpl = $options['body'] ?? '';
    }

    public static function sendHeaders( $extraHeaders = [], $selfCT = "" ) : void {
        if ( !isset( static::$app ) ) {
            throw new \Exception( "You should run init( App ) before this." );
        }

        !mb_strlen( $selfCT ) ? header( "Content-Type: text/html; charset=utf-8" ) : header( "Content-Type: {$selfCT}; charset=utf-8" );
		header( "X-Frame-Options: SAMEORIGIN" );
		//header( "Cache-Control: no-cache, no-store, must-revalidate" );
		//header( "Pragma: no-cache" );
        //header( "Expires: 0" );
        
        foreach( $extraHeaders as $header ) {
            header( $header );
        }
    }

    public static function displayPage() : void {
        if ( !isset( static::$app ) ) {
            throw new \Exception( "You should run init( App ) before this." );
        }

        if ( isset( static::$tpl ) && is_string( static::$tpl ) ) {
            echo static::$tpl;
        }

        exit();
    }
}
