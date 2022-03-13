<?php

namespace CarInsurance;

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

require 'vendor/autoload.php';

class Api {
    private App $app;

    public function __construct( App &$app, array $options = [] ) {
        $this->app = &$app;
        
        if ( empty( $this->app->query ) ) {
            Template::error( '$this->app->query is empty', 1 );
        }

        switch( $this->app->query ) {
            case Endpoints::API_AUTHORIZATION:
                $this->authorization();
            break;

            case Endpoints::API_AUTHSTATS:
                $this->authStats();
            break;

            case Endpoints::API_LOGS:
                $this->actionsLogs();
            break;

            case Endpoints::API_ACCOUNTS:
                $this->users();
            break;

            case Endpoints::API_RESOURCES:
                $this->resources();
            break;

            case Endpoints::API_CATEGORIES:
                $this->categories();
            break;

            case Endpoints::API_MAIN_PRODUCTS:
                $this->mainProducts();
            break;

            case Endpoints::API_SUB_PRODUCTS:
                $this->subProducts();
            break;

            case Endpoints::API_VEHICLES:
                $this->vehicles();
            break;

            case Endpoints::API_RATING:
                $this->rating();
            break;

            case Endpoints::API_ESTIMATIONS:
                $this->estimations();
            break;

            case Endpoints::API_ORDERS:
                $this->orders();
            break;

            case Endpoints::API_ASSETS:
                $this->assets();
            break;

            default:
                $this->printError( 501, 105 );
            break;
        }
    }

    private function sendMail( array $options = [] ) : bool {
        if ( !$options['to'] || !$options['subject'] || !$options['body'] ) {
            $this->printError( 500, 1018 );
        }

        //Create an instance; passing `true` enables exceptions
        $mail = new PHPMailer(true);

        try {
            //Server settings
            $mail->CharSet = 'UTF-8';
            $mail->Encoding = 'base64';
            $mail->SMTPDebug = SMTP::DEBUG_OFF;
            $mail->isSMTP();
            $mail->Host       = Settings::MAIL['Host'];
            $mail->SMTPAuth   = Settings::MAIL['SMTPAuth'];
            $mail->Username   = Settings::MAIL['Username'];
            $mail->Password   = Settings::MAIL['Password'];
            $mail->SMTPSecure = Settings::MAIL['SMTPSecure'];
            $mail->Port       = Settings::MAIL['Port'];

            //Recipients
            $mail->setFrom( Settings::FROM_EMAIL, Settings::FROM_NAME );
            $mail->addAddress( $options['to'] );

            //Content
            $mail->isHTML(true);
            $mail->Subject = $options['subject'];
            $mail->Body    = $options['body'];
            $mail->AltBody = strip_tags( $options['body'] );

            $mail->send();
            return true;
        } catch (Exception) {
            //echo "Message could not be sent. Mailer Error: {$mail->ErrorInfo}";
            return false;
        }
    }

    private function checkAccessLevel( bool $anonymousIsAllowed = false ) : void {
        $dt = new \DateTime();
        $currentTime = $dt->getTimestamp();

        $this->app->ip_addr = $this->app->db->escape( $this->app->ip_addr );

        $this->app->db->query( "DELETE FROM sessions WHERE expires < {$currentTime}" );

        $accessToken = $_SERVER['HTTP_AUTHORIZATION'] ?? "";
        $accessToken = trim( str_replace( 'Bearer ', '', $accessToken ) );

        if ( !mb_strlen( $accessToken ) && !$anonymousIsAllowed ) {
            $this->printError( 401, 107 );
        }

        $accessToken = $this->app->db->escape( $accessToken );
        $accessTokenHashed = hash_hmac( "sha256", $accessToken, Settings::ACCESS_TOKEN_HASH_SECRET );

        $q0 = $this->app->db->query( "SELECT * FROM sessions 
            WHERE access_token = \"{$accessTokenHashed}\" AND expires >= {$currentTime}" );

        $numRows = $q0->num_rows;

        if ( !$numRows && !$anonymousIsAllowed ) {
            $this->printError( 401, 108 );
        }
        else if ( !$numRows && $anonymousIsAllowed ) {
            $this->app->user = [];
            $this->app->user['user_id'] = 0;
            $this->app->user['user_uuid'] = '00000000-0000-0000-0000-000000000000';
            $this->app->user['role_id'] = 0;
            $this->app->user['role_title'] = 'anonymous';
        }
        else if ( $numRows ) {
            $session = $q0->fetch_assoc();
            $q0->free();

            $userId = intval( $session['user_id'] );

            $q1 = $this->app->db->query( "SELECT * FROM users WHERE user_id = {$userId} AND deleted = 0" );
            
            if ( !$q1->num_rows ) {
                $this->printError( 403, 131 );
            }

            $this->app->user = $q1->fetch_assoc();
            $q1->free();

            $userIsBanned = boolval( $this->app->user['banned'] );

            if ( $userIsBanned ) {
                $this->printError( 403, 133 );
            }

            $this->app->user['user_id'] = intval( $this->app->user['user_id'] );
            $this->app->user['role_id'] = intval( $this->app->user['role_id'] );

            $q2 = $this->app->db->query( "SELECT role FROM roles where role_id = {$this->app->user['role_id']}" );

            if ( !$q2->num_rows ) {
                $this->printError( 500, 1002 );
            }

            $this->app->user['role_title'] = $q2->fetch_assoc()['role'];
            $q2->free();

            $this->app->db->query( "UPDATE users SET last_activity = {$currentTime} WHERE user_id = {$userId}" );
        }
    }

    private function getAccessToken() : array {
        $accessToken = hash( 'sha256', random_bytes(16) );

        $dt = new \DateTime();
        $accessTokenCreatedTimestamp = $dt->getTimestamp();

        $dt->add( new \DateInterval( Settings::TOKEN_EXPIRATION_INTERVAL ) );
        $accessTokenExpiresTimestamp = $dt->getTimestamp();
        $accessTokenExpires = $this->formatDateTimeRepresentation( $dt );

        return [ $accessToken, $accessTokenCreatedTimestamp, $accessTokenExpiresTimestamp, $accessTokenExpires ];
    }

    public function authorization() : void {
        if ( $this->app->requestMethod !== 'POST' )
            $this->printError( 405, 106 );

        $dt = new \DateTime();
        $currentTime = $dt->getTimestamp();

        $dt->sub( new \DateInterval( Settings::AUTH_ATTEMPTS_INTERVAL ) );
        $banTime = $dt->getTimestamp();

        $this->app->db->query( "DELETE FROM auth_attempts WHERE last_time < {$banTime}" );

        $q0 = $this->app->db->query( "SELECT * FROM auth_attempts WHERE ip = \"{$this->app->ip_addr}\" AND last_time >= {$banTime}" );

        if ( $attempts = $q0->num_rows ) {
            if ( $attempts >= Settings::AUTH_ATTEMPTS ) {
                $this->printError( 429, 104 );
            }

            $q0->free();
        }

        $this->app->db->query( "INSERT INTO auth_attempts SET ip = \"{$this->app->ip_addr}\", last_time = {$currentTime}" );

        $data = trim( @file_get_contents('php://input') );
        $data = @json_decode( $data );

        if ( !is_object( $data ) || empty( $data->email ) || empty( $data->password ) ) {
            $this->printError( 403, 101 );
        }

        $email = $this->app->db->escape( $data->email );
        $password = $data->password;

        $q1 = $this->app->db->query( "SELECT * FROM users WHERE email = \"{$email}\" AND deleted = 0" );
        
        if ( !$q1->num_rows ) {
            $this->printError( 403, 102 );
        }

        $this->app->user = $q1->fetch_assoc();
        $q1->free();

        if ( !password_verify( $password, $this->app->user['pswd_h'] ) ) {
            $this->printError( 403, 102 );
        }

        $userIsBanned = boolval( $this->app->user['banned'] );

        if ( $userIsBanned ) {
            $this->printError( 403, 132 );
        }

        $this->app->user['user_id'] = intval( $this->app->user['user_id'] );
        $this->app->user['role_id'] = intval( $this->app->user['role_id'] );

        $q2 = $this->app->db->query( "SELECT role FROM roles where role_id = {$this->app->user['user_id']}" );

        if ( !$q2->num_rows ) {
            $this->printError( 500, 1002 );
        }

        $this->app->user['role_title'] = $q2->fetch_assoc()['role'];
        $q2->free();

        [ $accessToken, $accessTokenCreatedTimestamp, $accessTokenExpiresTimestamp, $accessTokenExpires ] = $this->getAccessToken();

        $accessTokenHashed = hash_hmac( "sha256", $accessToken, Settings::ACCESS_TOKEN_HASH_SECRET );

        $this->app->db->query( "DELETE FROM sessions WHERE expires < {$currentTime}" );

        $this->app->db->query( "INSERT INTO sessions SET 
            user_id = {$this->app->user['user_id']}, 
            ip = \"{$this->app->ip_addr}\", 
            access_token = \"{$accessTokenHashed}\",
            created = {$accessTokenCreatedTimestamp},
            expires = {$accessTokenExpiresTimestamp}
        " );

        $country = $this->app->db->escape( $this->app->geo_country );
        $userAgent = $this->app->db->escape( $this->app->user_agent );

        $this->app->db->query( "INSERT INTO authentications SET 
            user_id = {$this->app->user['user_id']}, 
            ip = \"{$this->app->ip_addr}\", 
            country = \"{$country}\", 
            user_agent = \"{$userAgent}\",
            created = {$accessTokenCreatedTimestamp}
        " );

        $this->printResponse([
            'token' => $accessToken,
            'tokenExpirationTime' => $accessTokenExpires,
            'accountId' => $this->app->user['user_uuid'],
            'email' => $this->app->user['email'],
            'username' => $this->app->user['username'],
            'role' => $this->app->user['role_title'],
            'firstName' => $this->app->user['first_name'],
            'lastName' => $this->app->user['last_name'],
        ]);
    }

    public function authStats() : void {
        $this->checkAccessLevel( anonymousIsAllowed: false );

        $myRole = $this->app->user['role_title'];
        $myUserId = $this->app->user['user_id'];
        
        $dt = new \DateTime();
        $currentTime = $dt->getTimestamp();

        if ( $this->app->requestMethod === 'GET' ) {
            $userUuid = $myRole === 'admin' ? $this->app->db->escape( $this->app->get['accountId'] ?? "" ) : $this->app->user['user_uuid'];

            $authCount = 0;

            if ( mb_strlen( $userUuid ) > 0 ) {
                $offset = intval( $this->app->get['offset'] ?? 0 );
                $limit = intval( $this->app->get['limit'] ?? Settings::PAGINATION_MAX_LIMIT );
                $limit = $limit <= Settings::PAGINATION_MAX_LIMIT ? $limit : Settings::PAGINATION_MAX_LIMIT;

                $q0 = $this->app->db->query( "SELECT * FROM users WHERE user_uuid = \"{$userUuid}\"" );

                if ( !$q0->num_rows ) {
                    $this->printError( 400, 2210 );
                }

                $user = $q0->fetch_assoc();
                $q0->free();

                $userId = intval( $user['user_id'] );

                $q1 = $this->app->db->query( "SELECT * FROM authentications WHERE user_id = {$userId} ORDER BY created DESC LIMIT {$offset}, {$limit}" );

                $q2 = $this->app->db->query( "SELECT COUNT(*) AS table_rows FROM authentications WHERE user_id = {$userId}" );

                if ( !$q2->num_rows ) {
                    $authCount = 0;
                }
                else {
                    $authCount = intval( $q2->fetch_assoc()['table_rows'] );
                    $q2->free();
                }
            }
            else {
                $offset = intval( $this->app->get['offset'] ?? 0 );
                $limit = intval( $this->app->get['limit'] ?? Settings::PAGINATION_MAX_LIMIT );
                $limit = $limit <= Settings::PAGINATION_MAX_LIMIT ? $limit : Settings::PAGINATION_MAX_LIMIT;

                $q1 = $this->app->db->query( "SELECT * FROM authentications ORDER BY created DESC LIMIT {$offset}, {$limit}" );

                $q2 = $this->app->db->query( "SELECT COUNT(*) AS table_rows FROM authentications " );

                if ( !$q2->num_rows ) {
                    $authCount = 0;
                }
                else {
                    $authCount = intval( $q2->fetch_assoc()['table_rows'] );
                    $q2->free();
                }
            }

            $authentications = [];
            $dt = new \DateTime();

            while( $auth = $q1->fetch_assoc() ) {
                $userId = intval( $auth['user_id'] );

                $q0 = $this->app->db->query( "SELECT * FROM users WHERE user_id = {$userId}" );

                if ( !$q0->num_rows ) {
                    continue;
                }

                $user = $q0->fetch_assoc();
                $q0->free();

                $dt->setTimestamp( intval( $auth['created'] ) );
                $authCreated = $this->formatDateTimeRepresentation( $dt );

                if ( $myRole === 'admin' ) {
                    $authentications[] = [
                        'accountId' => $user['user_uuid'],
                        'username' => $user['username'],
                        'email' => $user['email'],
                        'firstName' => $user['first_name'],
                        'lastName' => $user['last_name'],
                        'ipAddress' => $auth['ip'],
                        'country' => $auth['country'],
                        'userAgent' => $auth['user_agent'],
                        'loggedIn' => $authCreated,
                    ];
                }
                else {
                    $authentications[] = [
                        'accountId' => $user['user_uuid'],
                        'username' => $user['username'],
                        'email' => $user['email'],
                        'firstName' => $user['first_name'],
                        'lastName' => $user['last_name'],
                        'ipAddress' => $auth['ip'],
                        'country' => $auth['country'],
                        'userAgent' => $auth['user_agent'],
                        'loggedIn' => $authCreated,
                    ];
                }
            }

            $q1->free();

            $authentications = [
                "count" => $authCount,
                "authentications" => $authentications
            ];

            $this->printResponse( $authentications );
        }
        else {
            $this->printError( 405, 106 );
        }
    }

    public function actionsLogs() : void {
        $this->checkAccessLevel( anonymousIsAllowed: false );

        $myRole = $this->app->user['role_title'];
        $myUserId = $this->app->user['user_id'];

        $dt = new \DateTime();
        $currentTime = $dt->getTimestamp();

        if ( $this->app->requestMethod === 'GET' ) {
            if ( $myRole !== 'admin' ) {
                $this->printError( 403, 103 );
            }

            $userUuid =$this->app->db->escape( $this->app->get['accountId'] ?? "" );
            $userRole = $this->app->db->escape( $this->app->get['role'] ?? "" );
            $actionType = $this->app->db->escape( $this->app->get['action'] ?? "" );
            $description = $this->app->db->escape( $this->app->get['description'] ?? "" );

            $logsCount = 0;

            if ( mb_strlen( $userUuid ) > 0 ) {
                $offset = intval( $this->app->get['offset'] ?? 0 );
                $limit = intval( $this->app->get['limit'] ?? Settings::PAGINATION_MAX_LIMIT );
                $limit = $limit <= Settings::PAGINATION_MAX_LIMIT ? $limit : Settings::PAGINATION_MAX_LIMIT;

                $q1 = $this->app->db->query( "SELECT * FROM actions WHERE user_uuid = \"{$userUuid}\" ORDER BY created DESC LIMIT {$offset}, {$limit}" );

                $q2 = $this->app->db->query( "SELECT COUNT(*) AS table_rows FROM actions WHERE user_uuid = \"{$userUuid}\"" );

                if ( !$q2->num_rows ) {
                    $logsCount = 0;
                }
                else {
                    $logsCount = intval( $q2->fetch_assoc()['table_rows'] );
                    $q2->free();
                }
            }
            else if ( mb_strlen( $userRole ) > 0 ) {
                $offset = intval( $this->app->get['offset'] ?? 0 );
                $limit = intval( $this->app->get['limit'] ?? Settings::PAGINATION_MAX_LIMIT );
                $limit = $limit <= Settings::PAGINATION_MAX_LIMIT ? $limit : Settings::PAGINATION_MAX_LIMIT;

                $q1 = $this->app->db->query( "SELECT * FROM actions WHERE role = \"{$userRole}\" ORDER BY created DESC LIMIT {$offset}, {$limit}" );

                $q2 = $this->app->db->query( "SELECT COUNT(*) AS table_rows FROM actions WHERE role = \"{$userRole}\"" );

                if ( !$q2->num_rows ) {
                    $logsCount = 0;
                }
                else {
                    $logsCount = intval( $q2->fetch_assoc()['table_rows'] );
                    $q2->free();
                }
            }
            else if ( mb_strlen( $actionType ) > 0 ) {
                $offset = intval( $this->app->get['offset'] ?? 0 );
                $limit = intval( $this->app->get['limit'] ?? Settings::PAGINATION_MAX_LIMIT );
                $limit = $limit <= Settings::PAGINATION_MAX_LIMIT ? $limit : Settings::PAGINATION_MAX_LIMIT;

                $q1 = $this->app->db->query( "SELECT * FROM actions WHERE action = \"{$actionType}\" ORDER BY created DESC LIMIT {$offset}, {$limit}" );

                $q2 = $this->app->db->query( "SELECT COUNT(*) AS table_rows FROM actions WHERE action = \"{$actionType}\"" );

                if ( !$q2->num_rows ) {
                    $logsCount = 0;
                }
                else {
                    $logsCount = intval( $q2->fetch_assoc()['table_rows'] );
                    $q2->free();
                }
            }
            else if ( mb_strlen( $description ) > 0 ) {
                $offset = intval( $this->app->get['offset'] ?? 0 );
                $limit = intval( $this->app->get['limit'] ?? Settings::PAGINATION_MAX_LIMIT );
                $limit = $limit <= Settings::PAGINATION_MAX_LIMIT ? $limit : Settings::PAGINATION_MAX_LIMIT;

                $q1 = $this->app->db->query( "SELECT * FROM actions WHERE description = \"{$description}\" ORDER BY created DESC LIMIT {$offset}, {$limit}" );

                $q2 = $this->app->db->query( "SELECT COUNT(*) AS table_rows FROM actions WHERE description = \"{$description}\"" );

                if ( !$q2->num_rows ) {
                    $logsCount = 0;
                }
                else {
                    $logsCount = intval( $q2->fetch_assoc()['table_rows'] );
                    $q2->free();
                }
            }
            else {
                $offset = intval( $this->app->get['offset'] ?? 0 );
                $limit = intval( $this->app->get['limit'] ?? Settings::PAGINATION_MAX_LIMIT );
                $limit = $limit <= Settings::PAGINATION_MAX_LIMIT ? $limit : Settings::PAGINATION_MAX_LIMIT;

                $q1 = $this->app->db->query( "SELECT * FROM actions ORDER BY created DESC LIMIT {$offset}, {$limit}" );

                $q2 = $this->app->db->query( "SELECT COUNT(*) AS table_rows FROM actions" );

                if ( !$q2->num_rows ) {
                    $logsCount = 0;
                }
                else {
                    $logsCount = intval( $q2->fetch_assoc()['table_rows'] );
                    $q2->free();
                }
            }

            $actions = [];
            $dt = new \DateTime();

            while( $action = $q1->fetch_assoc() ) {
                $dt->setTimestamp( intval( $action['created'] ) );
                $actionCreated = $this->formatDateTimeRepresentation( $dt );

                $actions[] = [
                    'actionDatabaseId' => intval( $action['action_id'] ),
                    'accountId' => $action['user_uuid'],
                    'username' => $action['username'],
                    'role' => $action['role'],
                    'affectedAccountId' => $action['to_user_uuid'],
                    'affectedUsername' => $action['to_username'],
                    'action' => $action['action'],
                    'fields' => $action['fields'],
                    'whereClause' => $action['where_clause'],
                    'description' => $action['description'],
                    'created' => $actionCreated,
                ];
            }

            $q1->free();

            $actions = [
                "count" => $logsCount,
                "actions" => $actions
            ];

            $this->printResponse( $actions );
        }
        else {
            $this->printError( 405, 106 );
        }
    }

    public function resources() : void {
        $this->checkAccessLevel( anonymousIsAllowed: true );

        $myRole = $this->app->user['role_title'];
        $myUserId = $this->app->user['user_id'];

        $dt = new \DateTime();
        $currentTime = $dt->getTimestamp();

        if ( $this->app->requestMethod === 'GET' ) {
            $key = $this->app->db->escape( $this->app->get['resourceKey'] ?? "" );
            $showDeleted = $myRole === 'admin' ? boolval( $this->app->get['showDeleted'] ?? false ) : false;

            $sqlWhereAndConditionHideDeleted = !$showDeleted ? " AND deleted = 0" : "";
            $sqlWhereConditionHideDeleted = !$showDeleted ? " WHERE deleted = 0" : "";

            $resCount = 0;

            if ( mb_strlen( $key ) > 0 ) {
                $q1 = $this->app->db->query( "SELECT * FROM resources WHERE r_key = \"{$key}\"{$sqlWhereAndConditionHideDeleted}" );
                $resCount = 1;
            }
            else {
                $offset = intval( $this->app->get['offset'] ?? 0 );
                $limit = intval( $this->app->get['limit'] ?? Settings::PAGINATION_MAX_LIMIT );
                $limit = $limit <= Settings::PAGINATION_MAX_LIMIT ? $limit : Settings::PAGINATION_MAX_LIMIT;

                $q1 = $this->app->db->query( "SELECT * FROM resources{$sqlWhereConditionHideDeleted} ORDER BY resource_id ASC LIMIT {$offset}, {$limit}" );

                $q2 = $this->app->db->query( "SELECT COUNT(*) AS table_rows FROM resources{$sqlWhereConditionHideDeleted}" );

                if ( !$q2->num_rows ) {
                    $resCount = 0;
                }
                else {
                    $resCount = intval( $q2->fetch_assoc()['table_rows'] );
                    $q2->free();
                }
            }

            $resources = [];
            $dt = new \DateTime();

            while( $resource = $q1->fetch_assoc() ) {
                $resources[] = [
                    'resourceKey' => $resource['r_key'],
                    'resourceValue' => $resource['r_value'],
                    'deleted' => boolval( $resource['deleted'] ),
                ];
            }

            $q1->free();

            $resCount = count( $resources );

            $resources = [
                "count" => $resCount,
                "resources" => $resources
            ];

            $this->printResponse( $resources );
        }
        else if ( $this->app->requestMethod === 'POST' ) {
            if ( $myRole !== 'admin' ) {
                $this->printError( 403, 103 );
            }

            $data = trim( @file_get_contents('php://input') );
            $data = @json_decode( $data );

            if ( !is_object( $data ) ) {
                $this->printError( 403, 1090 );
            }

            $resourcesTableDataset = [];

            $resourceKey = $this->app->db->escape( $data->resourceKey ?? "" );

            if ( !$resourceKey ) {
                $this->printError( 403, 2310 );
            }

            $resourcesTableDataset['r_key'] = $resourceKey;

            $resourcesTableDataset['r_value'] = $this->app->db->escape( $data->resourceValue ?? "" );

            if ( isset( $data->deleted ) )
                $resourcesTableDataset['deleted'] = intval( $data->deleted ) > 0 ? 1 : 0;

            $mode = '';

            $q1 = $this->app->db->query( "SELECT resource_id FROM resources WHERE r_key = \"{$resourceKey}\"" );

            if ( $q1->num_rows ) {
                $mode = 'update';
                $q1->free();
            }
            else {
                unset( $resourcesTableDataset['deleted'] );
                $mode = 'create';
            }

            $sqlSliceResource = [];

            foreach( $resourcesTableDataset as $key => $value ) {
                if ( is_int( $value ) || is_float( $value ) )
                    $sqlSliceResource[] = "{$key} = {$value}";
                else
                    $sqlSliceResource[] = "{$key} = \"{$value}\"";
            }

            $sqlSliceResource = implode( ", ", $sqlSliceResource );

            if ( $mode === 'create' ) {
                if ( empty( $resourcesTableDataset['r_value'] ) ) {
                    $this->printError( 403, 2311 );
                }

                $this->app->db->query( "INSERT INTO resources SET {$sqlSliceResource}" );
                $resourceId = intval( $this->app->db->insert_id );

                if ( !$resourceId ) {
                    $this->printError( 500, 1019 );
                }

                $actionsTableDataset = [
                    'user_uuid' => $this->app->user['user_uuid'],
                    'username' => $this->app->user['username'],
                    'role' => $this->app->user['role_title'],
                    'to_user_uuid' => '',
                    'to_username' => '',
                    'entity_id' => $resourceId,
                    'action' => 'insert',
                    'fields' => $this->app->db->escape( $sqlSliceResource ),
                    'where_clause' => '',
                    'description' => 'inserted resource',
                    'created' => $currentTime,
                    'deleted' => 0 
                ];

                $this->setLog( $actionsTableDataset );
            }
            else if ( $mode === 'update' ) {
                $this->app->db->query( "UPDATE resources SET {$sqlSliceResource} WHERE r_key = \"{$resourceKey}\"" );

                $actionsTableDataset = [
                    'user_uuid' => $this->app->user['user_uuid'],
                    'username' => $this->app->user['username'],
                    'role' => $this->app->user['role_title'],
                    'to_user_uuid' => '',
                    'to_username' => '',
                    'entity_id' => '',
                    'action' => 'update',
                    'fields' => $this->app->db->escape( $sqlSliceResource ),
                    'where_clause' => $this->app->db->escape( "r_key = \"{$resourceKey}\"" ),
                    'description' => 'updated resource',
                    'created' => $currentTime,
                    'deleted' => 0 
                ];
    
                $this->setLog( $actionsTableDataset );
            }

            $this->printResponse([
                'resourceKey' => $resourceKey,
                'resourceValue' => $resourcesTableDataset['r_value'],
                'deleted' => boolval( $resourcesTableDataset['deleted'] ?? false ),
            ]);
        }
        else {
            $this->printError( 405, 106 );
        }
    }

    public function categories() : void {
        $this->checkAccessLevel( anonymousIsAllowed: true );

        $myRole = $this->app->user['role_title'];
        $myUserId = $this->app->user['user_id'];

        $dt = new \DateTime();
        $currentTime = $dt->getTimestamp();

        if ( $this->app->requestMethod === 'GET' ) {
            $categoryUuid = $this->app->db->escape( $this->app->get['categoryId'] ?? "" );
            $showDeleted = $myRole === 'admin' ? boolval( $this->app->get['showDeleted'] ?? false ) : false;

            $sqlWhereAndConditionHideDeleted = !$showDeleted ? " AND deleted = 0" : "";
            $sqlWhereConditionHideDeleted = !$showDeleted ? " WHERE deleted = 0" : "";

            $categoriesCount = 0;

            if ( mb_strlen( $categoryUuid ) > 0 ) {
                $q1 = $this->app->db->query( "SELECT * FROM categories WHERE category_uuid = \"{$categoryUuid}\"{$sqlWhereAndConditionHideDeleted}" );
                $categoriesCount = 1;
            }
            else {
                $offset = intval( $this->app->get['offset'] ?? 0 );
                $limit = intval( $this->app->get['limit'] ?? Settings::PAGINATION_MAX_LIMIT );
                $limit = $limit <= Settings::PAGINATION_MAX_LIMIT ? $limit : Settings::PAGINATION_MAX_LIMIT;

                $q1 = $this->app->db->query( "SELECT * FROM categories{$sqlWhereConditionHideDeleted} ORDER BY category_id ASC LIMIT {$offset}, {$limit}" );

                $q2 = $this->app->db->query( "SELECT COUNT(*) AS table_rows FROM categories{$sqlWhereConditionHideDeleted}" );

                if ( !$q2->num_rows ) {
                    $categoriesCount = 0;
                }
                else {
                    $categoriesCount = intval( $q2->fetch_assoc()['table_rows'] );
                    $q2->free();
                }
            }

            if ( !$q1->num_rows ) {
                $this->printError( 404, 141 );
            }

            $categories = [];
            $dt = new \DateTime();

            while( $category = $q1->fetch_assoc() ) {
                $categoryId = intval( $category['category_id'] );

                $dt->setTimestamp( intval( $category['created'] ) );
                $categoryCreated = $this->formatDateTimeRepresentation( $dt );

                $dt->setTimestamp( intval( $category['updated'] ) );
                $categoryUpdated = $this->formatDateTimeRepresentation( $dt );

                if ( $myRole === 'admin' ) {
                    $categories[] = [
                        'categoryId' => $category['category_uuid'],
                        'categoryName' => $category['category_name'],
                        'created' => $categoryCreated,
                        'updated' => $categoryUpdated,
                        'deleted' => boolval( $category['deleted'] ),
                    ];
                }
                else {
                    $categories[] = [
                        'categoryId' => $category['category_uuid'],
                        'categoryName' => $category['category_name'],
                    ];
                }
            }

            $q1->free();

            $categories = [
                "count" => $categoriesCount,
                "categories" => $categories
            ];

            $this->printResponse( $categories );
        }
        else if ( $this->app->requestMethod === 'POST' ) {
            if ( $myRole !== 'admin' ) {
                $this->printError( 403, 103 );
            }

            $data = trim( @file_get_contents('php://input') );
            $data = @json_decode( $data );

            if ( !is_object( $data ) ) {
                $this->printError( 403, 1090 );
            }

            $categoryUuid = $this->app->db->escape( $data->categoryId ?? "" );

            $categoriesTableDataset = [];

            if ( !empty( $data->categoryName ) )
                $categoriesTableDataset['category_name'] = $this->app->db->escape( $data->categoryName );

            if ( isset( $data->deleted ) )
                $categoriesTableDataset['deleted'] = intval( $data->deleted ) > 0 ? 1 : 0;

            $mode = '';

            if ( mb_strlen( $categoryUuid ) > 0 )
                $mode = 'update';
            else
                $mode = 'create';
            

            if ( $mode === 'create' ) {
                $categoriesTableDataset['category_uuid'] = Utils::generateUUID4();
                $categoriesTableDataset['category_name'] ??= "";
                $categoriesTableDataset['created'] = $currentTime;
                $categoriesTableDataset['updated'] = 0;
                $categoriesTableDataset['deleted'] ??= 0;

                if ( empty( $categoriesTableDataset['category_name'] ) || mb_strlen( $categoriesTableDataset['category_name'] ) < 1 ) {
                    $this->printError( 403, 1410 );
                }

                $sqlSliceCategory = [];

                foreach( $categoriesTableDataset as $key => $value ) {
                    if ( is_int( $value ) || is_float( $value ) )
                        $sqlSliceCategory[] = "{$key} = {$value}";
                    else
                        $sqlSliceCategory[] = "{$key} = \"{$value}\"";
                }

                $sqlSliceCategory = implode( ", ", $sqlSliceCategory );

                $this->app->db->query( "INSERT INTO categories SET {$sqlSliceCategory}" );
                $categoryId = intval( $this->app->db->insert_id );

                if ( !$categoryId ) {
                    $this->printError( 500, 1007 );
                }

                $actionsTableDataset = [
                    'user_uuid' => $this->app->user['user_uuid'],
                    'username' => $this->app->user['username'],
                    'role' => $this->app->user['role_title'],
                    'to_user_uuid' => '',
                    'to_username' => '',
                    'entity_id' => $categoryId,
                    'action' => 'insert',
                    'fields' => $this->app->db->escape( $sqlSliceCategory ),
                    'where_clause' => '',
                    'description' => 'inserted category',
                    'created' => $currentTime,
                    'deleted' => 0 
                ];

                $this->setLog( $actionsTableDataset );

                $q10 = $this->app->db->query( "SELECT * FROM categories WHERE category_id = {$categoryId}" );
            }
            else if ( $mode === 'update' ) {
                $categoriesTableDataset['updated'] = $currentTime;

                $sqlSliceCategory = [];

                foreach( $categoriesTableDataset as $key => $value ) {
                    if ( is_int( $value ) || is_float( $value ) )
                        $sqlSliceCategory[] = "{$key} = {$value}";
                    else
                        $sqlSliceCategory[] = "{$key} = \"{$value}\"";
                }

                $sqlSliceCategory = implode( ", ", $sqlSliceCategory );

                $this->app->db->query( "UPDATE categories SET {$sqlSliceCategory} WHERE category_uuid = \"{$categoryUuid}\"" );

                $actionsTableDataset = [
                    'user_uuid' => $this->app->user['user_uuid'],
                    'username' => $this->app->user['username'],
                    'role' => $this->app->user['role_title'],
                    'to_user_uuid' => '',
                    'to_username' => '',
                    'entity_id' => '',
                    'action' => 'update',
                    'fields' => $this->app->db->escape( $sqlSliceCategory ),
                    'where_clause' => $this->app->db->escape( "category_uuid = \"{$categoryUuid}\"" ),
                    'description' => 'updated category',
                    'created' => $currentTime,
                    'deleted' => 0 
                ];
    
                $this->setLog( $actionsTableDataset );

                $q10 = $this->app->db->query( "SELECT * FROM categories WHERE category_uuid = \"{$categoryUuid}\"" );
            }

            if ( !$q10->num_rows ) {
                $this->printError( 404, 1007 );
            }

            $category = $q10->fetch_assoc();
            $q10->free();

            $dt = new \DateTime();

            $dt->setTimestamp( intval( $category['created'] ) );
            $categoryCreated = $this->formatDateTimeRepresentation( $dt );

            $dt->setTimestamp( intval( $category['updated'] ) );
            $categoryUpdated = $this->formatDateTimeRepresentation( $dt );

            $this->printResponse([
                'categoryId' => $category['category_uuid'],
                'categoryName' => $category['category_name'],
                'created' => $categoryCreated,
                'updated' => $categoryUpdated,
                'deleted' => boolval( $category['deleted'] ),
            ]);
        }
        else {
            $this->printError( 405, 106 );
        }
    }

    public function vehicles() : void {
        $this->checkAccessLevel( anonymousIsAllowed: false );

        $myRole = $this->app->user['role_title'];
        $myUserId = $this->app->user['user_id'];

        $dt = new \DateTime();
        $currentTime = $dt->getTimestamp();

        if ( $this->app->requestMethod === 'GET' ) {
            $vehicleUuid = $this->app->db->escape( $this->app->get['vehicleId'] ?? "" );
            $userUuid = $this->app->db->escape( $this->app->get['accountId'] ?? "" );
            $showDeleted = $myRole === 'admin' ? boolval( $this->app->get['showDeleted'] ?? false ) : false;

            $sqlWhereAndConditionHideDeleted = !$showDeleted ? " AND deleted = 0" : "";
            $sqlWhereConditionHideDeleted = !$showDeleted ? " WHERE deleted = 0" : "";

            $vehiclesCount = 0;
            $vehicles = [];

            if ( mb_strlen( $vehicleUuid ) > 0 ) {
                $q1 = $this->app->db->query( "SELECT * FROM vehicles WHERE vehicle_uuid = \"{$vehicleUuid}\"{$sqlWhereAndConditionHideDeleted}" );
                $vehiclesCount = 1;
            }
            else if ( mb_strlen( $userUuid ) > 0 ) {
                $offset = intval( $this->app->get['offset'] ?? 0 );
                $limit = intval( $this->app->get['limit'] ?? Settings::PAGINATION_MAX_LIMIT );
                $limit = $limit <= Settings::PAGINATION_MAX_LIMIT ? $limit : Settings::PAGINATION_MAX_LIMIT;

                $q0 = $this->app->db->query( "SELECT user_id FROM users WHERE user_uuid = \"{$userUuid}\"{$sqlWhereAndConditionHideDeleted}" );

                if ( !$q0->num_rows ) {
                    $this->printError( 400, 1710 );
                }

                $userId = intval( $q0->fetch_assoc()['user_id'] );
                $q0->free();

                $q1 = $this->app->db->query( "SELECT * FROM vehicles WHERE user_id = {$userId}{$sqlWhereAndConditionHideDeleted} ORDER BY created DESC LIMIT {$offset}, {$limit}" );

                $q2 = $this->app->db->query( "SELECT COUNT(*) AS table_rows FROM vehicles WHERE user_id = {$userId}{$sqlWhereAndConditionHideDeleted}" );

                if ( !$q2->num_rows ) {
                    $vehiclesCount = 0;
                }
                else {
                    $vehiclesCount = intval( $q2->fetch_assoc()['table_rows'] );
                    $q2->free();
                }
            }
            else {
                $offset = intval( $this->app->get['offset'] ?? 0 );
                $limit = intval( $this->app->get['limit'] ?? Settings::PAGINATION_MAX_LIMIT );
                $limit = $limit <= Settings::PAGINATION_MAX_LIMIT ? $limit : Settings::PAGINATION_MAX_LIMIT;

                $q1 = $this->app->db->query( "SELECT * FROM vehicles{$sqlWhereConditionHideDeleted} ORDER BY created DESC LIMIT {$offset}, {$limit}" );

                $q2 = $this->app->db->query( "SELECT COUNT(*) AS table_rows FROM vehicles{$sqlWhereConditionHideDeleted}" );

                if ( !$q2->num_rows ) {
                    $vehiclesCount = 0;
                }
                else {
                    $vehiclesCount = intval( $q2->fetch_assoc()['table_rows'] );
                    $q2->free();
                }
            }

            if ( !$q1->num_rows ) {
                $this->printError( 404, 171 );
            }

            $dt = new \DateTime();

            while( $vehicle = $q1->fetch_assoc() ) {
                $userId = intval( $vehicle['user_id'] );

                $q3 = $this->app->db->query( "SELECT * FROM users WHERE user_id = {$userId}{$sqlWhereAndConditionHideDeleted}" );

                if ( !$q3->num_rows ) {
                    continue;
                }

                $user = $q3->fetch_assoc();
                $q3->free();

                $dt->setTimestamp( intval( $vehicle['created'] ) );
                $vehicleCreated = $this->formatDateTimeRepresentation( $dt );

                $dt->setTimestamp( intval( $vehicle['updated'] ) );
                $vehicleUpdated = $this->formatDateTimeRepresentation( $dt );

                $assets = [];

                $q700 = $this->app->db->query( "SELECT * FROM assets WHERE related_to = \"vehicles\" AND relation_uuid = \"{$vehicle['vehicle_uuid']}\"" );

                while( $asset = $q700->fetch_assoc() ) {
                    $dt->setTimestamp( intval( $asset['created'] ) );
                    $assetCreated = $this->formatDateTimeRepresentation( $dt );

                    if ( $myRole === 'admin' ) {
                        $assets[] = [
                            'assetId' => $asset['asset_uuid'],
                            'relatedTo' => $asset['related_to'],
                            'description' => nl2br( $asset['description'] ),
                            'fileType' => $asset['file_type'],
                            'path' => $asset['path'],
                            'created' => $assetCreated,
                            'deleted' => boolval( $asset['deleted'] ),
                        ];
                    }
                    else {
                        $assets[] = [
                            'assetId' => $asset['asset_uuid'],
                            'relatedTo' => $asset['related_to'],
                            'description' => nl2br( $asset['description'] ),
                            'fileType' => $asset['file_type'],
                            'path' => $asset['path'],
                        ];
                    }
                }

                $q700->free();

                if ( $myRole === 'admin' ) {
                    $vehicles[] = [
                        'vehicleId' => $vehicle['vehicle_uuid'],
                        'accountId' => $user['user_uuid'],
                        'username' => $user['username'],
                        'firstName' => $user['first_name'],
                        'lastName' => $user['last_name'],
                        'details' => $vehicle['details'],
                        'assets' => $assets,
                        'regNumber' => $vehicle['reg_number'],
                        'vin' => $vehicle['vin'],
                        'engine' => $vehicle['engine'],
                        'overnightParkingVehicle' => $vehicle['overnight_parking_vehicle'],
                        'year' => intval( $vehicle['year'] ),
                        'retailValue' => intval( $vehicle['retail_value'] ),
                        'trackingDevice' => $vehicle['tracking_device'],
                        'useCase' => $vehicle['use_case'],
                        'businessDescription' => $vehicle['business_description'],
                        'accessories' => $vehicle['accessories'],
                        'created' => $vehicleCreated,
                        'updated' => $vehicleUpdated,
                        'deleted' => boolval( $vehicle['deleted'] ),
                    ];
                }
                else {
                    if ( $myUserId === $userId ) {
                        $vehicles[] = [
                            'vehicleId' => $vehicle['vehicle_uuid'],
                            'accountId' => $user['user_uuid'],
                            'username' => $user['username'],
                            'firstName' => $user['first_name'],
                            'lastName' => $user['last_name'],
                            'details' => $vehicle['details'],
                            'assets' => $assets,
                            'regNumber' => $vehicle['reg_number'],
                            'vin' => $vehicle['vin'],
                            'engine' => $vehicle['engine'],
                            'overnightParkingVehicle' => $vehicle['overnight_parking_vehicle'],
                            'year' => intval( $vehicle['year'] ),
                            'retailValue' => intval( $vehicle['retail_value'] ),
                            'trackingDevice' => $vehicle['tracking_device'],
                            'useCase' => $vehicle['use_case'],
                            'businessDescription' => $vehicle['business_description'],
                            'accessories' => $vehicle['accessories'],
                            'created' => $vehicleCreated,
                            'updated' => $vehicleUpdated,
                            'deleted' => boolval( $vehicle['deleted'] ),
                        ];
                    }
                }
            }

            $q1->free();

            if ( $myRole === 'anonymous' ) {
                $vehiclesCount = 0;
            }

            $vehicles = [
                "count" => $vehiclesCount,
                "vehicles" => $vehicles
            ];

            $this->printResponse( $vehicles );
        }
        else if ( $this->app->requestMethod === 'POST' ) {
            $data = trim( @file_get_contents('php://input') );
            $data = @json_decode( $data );

            if ( !is_object( $data ) ) {
                $this->printError( 403, 1090 );
            }

            $vehicleUuid = $this->app->db->escape( $data->vehicleId ?? "" );
            $userUuid = $myRole === 'admin' ? $this->app->db->escape( $data->accountId ?? $this->app->user['user_uuid'] ) : $this->app->user['user_uuid'];

            $vehiclesTableDataset = [];

            $user = [];
            $userId = 0;

            $q11 = $this->app->db->query( "SELECT * FROM users WHERE user_uuid = \"{$userUuid}\" AND deleted = 0" );

            if ( $q11->num_rows ) {
                $user = $q11->fetch_assoc();
                $userId = intval( $user['user_id'] );
                $q11->free();
            }

            $vehiclesTableDataset['user_id'] = $userId;

            if ( !empty( $data->details ) )
                $vehiclesTableDataset['details'] = $this->app->db->escape( $data->details );

            if ( !empty( $data->regNumber ) )
                $vehiclesTableDataset['reg_number'] = $this->app->db->escape( $data->regNumber );

            if ( !empty( $data->vin ) )
                $vehiclesTableDataset['vin'] = $this->app->db->escape( $data->vin );

            if ( !empty( $data->engine ) )
                $vehiclesTableDataset['engine'] = $this->app->db->escape( $data->engine );

            if ( !empty( $data->overnightParkingVehicle ) )
                $vehiclesTableDataset['overnight_parking_vehicle'] = $this->app->db->escape( $data->overnightParkingVehicle );

            if ( !empty( $data->year ) )
                $vehiclesTableDataset['year'] = intval( $data->year );

            if ( !empty( $data->retailValue ) )
                $vehiclesTableDataset['retail_value'] = intval( $data->retailValue );

            if ( !empty( $data->trackingDevice ) )
                $vehiclesTableDataset['tracking_device'] = $this->app->db->escape( $data->trackingDevice );


            if ( !empty( $data->useCase ) ) {
                $data->useCase = mb_strtolower( $data->useCase );

                if ( !in_array( needle: $data->useCase, haystack: [ "private", "business", "private and business" ], strict: true ) ) {
                    $this->printError( 403, 1713 );
                }

                $vehiclesTableDataset['use_case'] = $this->app->db->escape( $data->useCase );
            }

            if ( !empty( $data->businessDescription ) )
                $vehiclesTableDataset['business_description'] = $this->app->db->escape( $data->businessDescription );

            if ( !empty( $data->accessories ) )
                $vehiclesTableDataset['accessories'] = $this->app->db->escape( $data->accessories );

            $mode = '';

            if ( mb_strlen( $vehicleUuid ) > 0 )
                $mode = 'update';
            else
                $mode = 'create';
            

            if ( $mode === 'create' ) {
                $vehiclesTableDataset['vehicle_uuid'] = Utils::generateUUID4();
                $vehiclesTableDataset['retail_value'] ??= 0;
                $vehiclesTableDataset['created'] = $currentTime;
                $vehiclesTableDataset['updated'] = 0;
                $vehiclesTableDataset['deleted'] ??= 0;

                if ( !$userId ) {
                    $this->printError( 403, 1710 );
                }

                if ( empty( $vehiclesTableDataset['details'] ) || mb_strlen( $vehiclesTableDataset['details'] ) < 1 ) {
                    $this->printError( 403, 1712 );
                }

                if ( empty( $vehiclesTableDataset['use_case'] ) ) {
                    $this->printError( 403, 1713 );
                }

                $sqlSliceVehicle = [];

                foreach( $vehiclesTableDataset as $key => $value ) {
                    if ( is_int( $value ) || is_float( $value ) )
                        $sqlSliceVehicle[] = "{$key} = {$value}";
                    else
                        $sqlSliceVehicle[] = "{$key} = \"{$value}\"";
                }

                $sqlSliceVehicle = implode( ", ", $sqlSliceVehicle );

                $this->app->db->query( "INSERT INTO vehicles SET {$sqlSliceVehicle}" );
                $vehicleId = intval( $this->app->db->insert_id );

                if ( !$vehicleId ) {
                    $this->printError( 500, 1012 );
                }

                $actionsTableDataset = [
                    'user_uuid' => $this->app->user['user_uuid'],
                    'username' => $this->app->user['username'],
                    'role' => $this->app->user['role_title'],
                    'to_user_uuid' => '',
                    'to_username' => '',
                    'entity_id' => $vehicleId,
                    'action' => 'insert',
                    'fields' => $this->app->db->escape( $sqlSliceVehicle ),
                    'where_clause' => '',
                    'description' => 'inserted vehicle',
                    'created' => $currentTime,
                    'deleted' => 0 
                ];

                $this->setLog( $actionsTableDataset );

                $q10 = $this->app->db->query( "SELECT * FROM vehicles WHERE vehicle_id = {$vehicleId}" );
            }
            else if ( $mode === 'update' ) {
                if ( $myRole !== 'admin' ) {
                    $q16 = $this->app->db->query( "SELECT * FROM vehicles WHERE user_id = {$userId} AND vehicle_uuid = \"{$vehicleUuid}\"" );

                    if ( !$q16->num_rows ) {
                        $this->printError( 403, 1714 );
                    }

                    $q16->free();
                }
                else {
                    if ( isset( $data->deleted ) )
                        $vehiclesTableDataset['deleted'] = intval( $data->deleted ) > 0 ? 1 : 0;
                }

                // ставим через assets
                /*
                $vehiclePhotos = $data->vehiclePhotos ?? null;

                if ( is_array( $vehiclePhotos ) ) {
                    foreach( $vehiclePhotos as $key => $value ) {
                        if ( !Utils::startsWith( $value, "/assets/{$userUuid}/" ) ) {
                            unset( $vehiclePhotos[ $key ] );
                        }
                    }

                    $vehiclesTableDataset['vehicle_photos'] = $this->app->db->escape( json_encode( $vehiclePhotos, JSON_UNESCAPED_UNICODE ) );
                }
                */

                $vehiclesTableDataset['updated'] = $currentTime;

                if ( empty( $vehiclesTableDataset['use_case'] ) && !isset( $vehiclesTableDataset['deleted'] ) ) {
                    $this->printError( 403, 1713 );
                }

                $sqlSliceVehicle = [];

                foreach( $vehiclesTableDataset as $key => $value ) {
                    if ( is_int( $value ) || is_float( $value ) )
                        $sqlSliceVehicle[] = "{$key} = {$value}";
                    else
                        $sqlSliceVehicle[] = "{$key} = \"{$value}\"";
                }

                $sqlSliceVehicle = implode( ", ", $sqlSliceVehicle );

                $this->app->db->query( "UPDATE vehicles SET {$sqlSliceVehicle} WHERE vehicle_uuid = \"{$vehicleUuid}\"" );

                $actionsTableDataset = [
                    'user_uuid' => $this->app->user['user_uuid'],
                    'username' => $this->app->user['username'],
                    'role' => $this->app->user['role_title'],
                    'to_user_uuid' => '',
                    'to_username' => '',
                    'entity_id' => '',
                    'action' => 'update',
                    'fields' => $this->app->db->escape( $sqlSliceVehicle ),
                    'where_clause' => $this->app->db->escape( "vehicle_uuid = \"{$vehicleUuid}\"" ),
                    'description' => 'updated vehicle',
                    'created' => $currentTime,
                    'deleted' => 0 
                ];
    
                $this->setLog( $actionsTableDataset );

                $q10 = $this->app->db->query( "SELECT * FROM vehicles WHERE vehicle_uuid = \"{$vehicleUuid}\"" );
            }

            if ( !$q10->num_rows ) {
                $this->printError( 500, 1012 );
            }

            $vehicle = $q10->fetch_assoc();
            $q10->free();

            $dt = new \DateTime();

            $dt->setTimestamp( intval( $vehicle['created'] ) );
            $vehicleCreated = $this->formatDateTimeRepresentation( $dt );

            $dt->setTimestamp( intval( $vehicle['updated'] ) );
            $vehicleUpdated = $this->formatDateTimeRepresentation( $dt );

            $this->printResponse([
                'vehicleId' => $vehicle['vehicle_uuid'],
                'accountId' => $user['user_uuid'],
                'username' => $user['username'],
                'firstName' => $user['first_name'],
                'lastName' => $user['last_name'],
                'details' => $vehicle['details'],
                'regNumber' => $vehicle['reg_number'],
                'vin' => $vehicle['vin'],
                'engine' => $vehicle['engine'],
                'overnightParkingVehicle' => $vehicle['overnight_parking_vehicle'],
                'year' => intval( $vehicle['year'] ),
                'retailValue' => intval( $vehicle['retail_value'] ),
                'trackingDevice' => $vehicle['tracking_device'],
                'useCase' => $vehicle['use_case'],
                'businessDescription' => $vehicle['business_description'],
                'accessories' => $vehicle['accessories'],
                'created' => $vehicleCreated,
                'updated' => $vehicleUpdated,
                'deleted' => boolval( $vehicle['deleted'] ),
            ]);
        }
        else {
            $this->printError( 405, 106 );
        }
    }

    public function mainProducts() : void {
        $this->checkAccessLevel( anonymousIsAllowed: true );

        $myRole = $this->app->user['role_title'];
        $myUserId = $this->app->user['user_id'];

        $dt = new \DateTime();
        $currentTime = $dt->getTimestamp();

        if ( $this->app->requestMethod === 'GET' ) {
            $mainProductUuid = $this->app->db->escape( $this->app->get['mainProductId'] ?? "" );
            $categoryUuid = $this->app->db->escape( $this->app->get['categoryId'] ?? "" );
            $showDeleted = $myRole === 'admin' ? boolval( $this->app->get['showDeleted'] ?? false ) : false;

            $sqlWhereAndConditionHideDeleted = !$showDeleted ? " AND deleted = 0" : "";
            $sqlWhereConditionHideDeleted = !$showDeleted ? " WHERE deleted = 0" : "";

            $mainProductsCount = 0;

            if ( mb_strlen( $mainProductUuid ) > 0 ) {
                $q1 = $this->app->db->query( "SELECT * FROM main_products WHERE product_uuid = \"{$mainProductUuid}\"{$sqlWhereAndConditionHideDeleted}" );
                $mainProductsCount = 1;
            }
            else if ( mb_strlen( $categoryUuid ) > 0 ) {
                $offset = intval( $this->app->get['offset'] ?? 0 );
                $limit = intval( $this->app->get['limit'] ?? Settings::PAGINATION_MAX_LIMIT );
                $limit = $limit <= Settings::PAGINATION_MAX_LIMIT ? $limit : Settings::PAGINATION_MAX_LIMIT;

                $q0 = $this->app->db->query( "SELECT category_id FROM categories WHERE category_uuid = \"{$categoryUuid}\"{$sqlWhereAndConditionHideDeleted}" );

                if ( !$q0->num_rows ) {
                    $this->printError( 404, 1510 );
                }
    
                $categoryId = intval( $q0->fetch_assoc()['category_id'] );
                $q0->free();

                $q1 = $this->app->db->query( "SELECT * FROM main_products WHERE category_id = {$categoryId}{$sqlWhereAndConditionHideDeleted} ORDER BY main_product_id ASC LIMIT {$offset}, {$limit}" );

                $q2 = $this->app->db->query( "SELECT COUNT(*) AS table_rows FROM main_products WHERE category_id = {$categoryId}{$sqlWhereAndConditionHideDeleted}" );

                if ( !$q2->num_rows ) {
                    $mainProductsCount = 0;
                }
                else {
                    $mainProductsCount = intval( $q2->fetch_assoc()['table_rows'] );
                    $q2->free();
                }
            }
            else {
                $offset = intval( $this->app->get['offset'] ?? 0 );
                $limit = intval( $this->app->get['limit'] ?? Settings::PAGINATION_MAX_LIMIT );
                $limit = $limit <= Settings::PAGINATION_MAX_LIMIT ? $limit : Settings::PAGINATION_MAX_LIMIT;

                $q1 = $this->app->db->query( "SELECT * FROM main_products{$sqlWhereConditionHideDeleted} ORDER BY main_product_id ASC LIMIT {$offset}, {$limit}" );

                $q2 = $this->app->db->query( "SELECT COUNT(*) AS table_rows FROM main_products{$sqlWhereConditionHideDeleted}" );

                if ( !$q2->num_rows ) {
                    $mainProductsCount = 0;
                }
                else {
                    $mainProductsCount = intval( $q2->fetch_assoc()['table_rows'] );
                    $q2->free();
                }
            }

            if ( !$q1->num_rows ) {
                $this->printError( 404, 151 );
            }

            $mainProducts = [];
            $dt = new \DateTime();

            while ( $mainProduct = $q1->fetch_assoc() ) {
                $mainProductId = intval( $mainProduct['main_product_id'] );

                $dt->setTimestamp( intval( $mainProduct['created'] ) );
                $mainProductCreated = $this->formatDateTimeRepresentation( $dt );
    
                $dt->setTimestamp( intval( $mainProduct['updated'] ) );
                $mainProductUpdated = $this->formatDateTimeRepresentation( $dt );
    
                $categoryId = intval( $mainProduct['category_id'] );
    
                $q2 = $this->app->db->query( "SELECT * FROM categories WHERE category_id = {$categoryId}{$sqlWhereAndConditionHideDeleted}" );
    
                if ( !$q2->num_rows ) {
                    continue;
                }
    
                $category = $q2->fetch_assoc();
                $q2->free();

                $subProducts = [];

                $q13 = $this->app->db->query( "SELECT * FROM sub_products WHERE main_product_id = {$mainProductId}{$sqlWhereAndConditionHideDeleted}" );

                while( $subProduct = $q13->fetch_assoc() ) {
                    $dt->setTimestamp( intval( $subProduct['created'] ) );
                    $subProductCreated = $this->formatDateTimeRepresentation( $dt );

                    $dt->setTimestamp( intval( $subProduct['updated'] ) );
                    $subProductUpdated = $this->formatDateTimeRepresentation( $dt );

                    if ( $myRole === 'admin' ) {
                        $subProducts[] = [
                            'subProductId' => $subProduct['product_uuid'],
                            'subProductName' => $subProduct['product_name'],
                            'subProductDescription' => nl2br( $subProduct['product_description'] ),
                            'isRequired' => boolval( $subProduct['is_required'] ),
                            'subProductCost' => floatval( $subProduct['cost'] ),
                            'created' => $subProductCreated,
                            'updated' => $subProductUpdated,
                            'deleted' => boolval( $subProduct['deleted'] ),
                        ];
                    }
                    else {
                        $subProducts[] = [
                            'subProductId' => $subProduct['product_uuid'],
                            'subProductName' => $subProduct['product_name'],
                            'subProductDescription' => nl2br( $subProduct['product_description'] ),
                            'isRequired' => boolval( $subProduct['is_required'] ),
                            'subProductCost' => floatval( $subProduct['cost'] ),
                            'created' => $subProductCreated,
                            'updated' => $subProductUpdated,
                            'deleted' => boolval( $subProduct['deleted'] ),
                        ];
                    }
                }

                $q13->free();
    
                if ( $myRole === 'admin' ) {
                    $mainProducts[] = [
                        'mainProductId' => $mainProduct['product_uuid'],
                        'categoryId' => $category['category_uuid'],
                        'categoryName' => $category['category_name'],
                        'mainProductName' => $mainProduct['product_name'],
                        'mainProductDescription' => nl2br( $mainProduct['product_description'] ),
                        'isRequiredCoverages' => boolval( $mainProduct['is_required_coverages'] ),
                        'mainProductCost' => floatval( $mainProduct['cost'] ),
                        'subProducts' => $subProducts,
                        'created' => $mainProductCreated,
                        'updated' => $mainProductUpdated,
                        'deleted' => boolval( $mainProduct['deleted'] ),
                    ];
                }
                else {
                    $mainProducts[] = [
                        'mainProductId' => $mainProduct['product_uuid'],
                        'categoryId' => $category['category_uuid'],
                        'categoryName' => $category['category_name'],
                        'mainProductName' => $mainProduct['product_name'],
                        'mainProductDescription' => nl2br( $mainProduct['product_description'] ),
                        'isRequiredCoverages' => boolval( $mainProduct['is_required_coverages'] ),
                        'mainProductCost' => floatval( $mainProduct['cost'] ),
                        'subProducts' => $subProducts,
                        'created' => $mainProductCreated,
                        'updated' => $mainProductUpdated,
                        'deleted' => boolval( $mainProduct['deleted'] ),
                    ];
                }
            }

            $q1->free();

            $mainProducts = [
                "count" => $mainProductsCount,
                "mainProducts" => $mainProducts
            ];

            $this->printResponse( $mainProducts );
        }
        else if ( $this->app->requestMethod === 'POST' ) {
            if ( $myRole !== 'admin' ) {
                $this->printError( 403, 103 );
            }

            $data = trim( @file_get_contents('php://input') );
            $data = @json_decode( $data );

            if ( !is_object( $data ) ) {
                $this->printError( 403, 1090 );
            }

            $mainProductUuid = $this->app->db->escape( $data->mainProductId ?? "" );
            $categoryUuid = $this->app->db->escape( $data->categoryId ?? "" );

            $mainProductsTableDataset = [];

            $categoryId = 0;

            if ( mb_strlen( $categoryUuid ) > 0 ) {
                $q11 = $this->app->db->query( "SELECT category_id FROM categories WHERE category_uuid = \"{$categoryUuid}\"" );

                if ( !$q11->num_rows ) {
                    $this->printError( 403, 1510 );
                }

                $categoryId = intval( $q11->fetch_assoc()['category_id'] );
                $q11->free();

                $mainProductsTableDataset['category_id'] = $categoryId;
            }

            if ( !empty( $data->mainProductName ) )
                $mainProductsTableDataset['product_name'] = $this->app->db->escape( $data->mainProductName );

            if ( !empty( $data->mainProductDescription ) )
                $mainProductsTableDataset['product_description'] = $this->app->db->escape( $data->mainProductDescription );

            if ( isset( $data->isRequiredCoverages ) )
                $mainProductsTableDataset['is_required_coverages'] = intval( $data->isRequiredCoverages ) > 0 ? 1 : 0;

            if ( !empty( $data->cost ) )
                $mainProductsTableDataset['cost'] = floatval( $data->cost );

            if ( isset( $data->deleted ) )
                $mainProductsTableDataset['deleted'] = intval( $data->deleted ) > 0 ? 1 : 0;

            $mode = '';

            if ( mb_strlen( $mainProductUuid ) > 0 )
                $mode = 'update';
            else
                $mode = 'create';
            

            if ( $mode === 'create' ) {
                $mainProductsTableDataset['product_uuid'] = Utils::generateUUID4();
                $mainProductsTableDataset['product_name'] ??= "";
                $mainProductsTableDataset['product_description'] ??= "";
                $mainProductsTableDataset['is_required_coverages'] ??= 0;
                $mainProductsTableDataset['cost'] ??= 0.0;
                $mainProductsTableDataset['created'] = $currentTime;
                $mainProductsTableDataset['updated'] = 0;
                $mainProductsTableDataset['deleted'] ??= 0;

                if ( !$categoryId ) {
                    $this->printError( 403, 1510 );
                }

                if ( empty( $mainProductsTableDataset['product_name'] ) || mb_strlen( $mainProductsTableDataset['product_name'] ) < 1 ) {
                    $this->printError( 403, 1511 );
                }

                $sqlSliceMainProduct = [];

                foreach( $mainProductsTableDataset as $key => $value ) {
                    if ( is_int( $value ) || is_float( $value ) )
                        $sqlSliceMainProduct[] = "{$key} = {$value}";
                    else
                        $sqlSliceMainProduct[] = "{$key} = \"{$value}\"";
                }

                $sqlSliceMainProduct = implode( ", ", $sqlSliceMainProduct );

                $this->app->db->query( "INSERT INTO main_products SET {$sqlSliceMainProduct}" );
                $mainProductId = intval( $this->app->db->insert_id );

                if ( !$mainProductId ) {
                    $this->printError( 500, 1009 );
                }

                $actionsTableDataset = [
                    'user_uuid' => $this->app->user['user_uuid'],
                    'username' => $this->app->user['username'],
                    'role' => $this->app->user['role_title'],
                    'to_user_uuid' => '',
                    'to_username' => '',
                    'entity_id' => $mainProductId,
                    'action' => 'insert',
                    'fields' => $this->app->db->escape( $sqlSliceMainProduct ),
                    'where_clause' => '',
                    'description' => 'inserted main product',
                    'created' => $currentTime,
                    'deleted' => 0 
                ];

                $this->setLog( $actionsTableDataset );

                $q10 = $this->app->db->query( "SELECT * FROM main_products WHERE main_product_id = {$mainProductId}" );
            }
            else if ( $mode === 'update' ) {
                $mainProductsTableDataset['updated'] = $currentTime;

                $sqlSliceMainProduct = [];

                foreach( $mainProductsTableDataset as $key => $value ) {
                    if ( is_int( $value ) || is_float( $value ) )
                        $sqlSliceMainProduct[] = "{$key} = {$value}";
                    else
                        $sqlSliceMainProduct[] = "{$key} = \"{$value}\"";
                }

                $sqlSliceMainProduct = implode( ", ", $sqlSliceMainProduct );

                $this->app->db->query( "UPDATE main_products SET {$sqlSliceMainProduct} WHERE product_uuid = \"{$mainProductUuid}\"" );

                $actionsTableDataset = [
                    'user_uuid' => $this->app->user['user_uuid'],
                    'username' => $this->app->user['username'],
                    'role' => $this->app->user['role_title'],
                    'to_user_uuid' => '',
                    'to_username' => '',
                    'entity_id' => '',
                    'action' => 'update',
                    'fields' => $this->app->db->escape( $sqlSliceMainProduct ),
                    'where_clause' => $this->app->db->escape( "product_uuid = \"{$mainProductUuid}\"" ),
                    'description' => 'updated main product',
                    'created' => $currentTime,
                    'deleted' => 0 
                ];
    
                $this->setLog( $actionsTableDataset );

                $q10 = $this->app->db->query( "SELECT * FROM main_products WHERE product_uuid = \"{$mainProductUuid}\"" );
            }

            if ( !$q10->num_rows ) {
                $this->printError( 500, 1009 );
            }

            $mainProduct = $q10->fetch_assoc();
            $q10->free();

            $categoryId = intval( $mainProduct['category_id'] );

            $q11 = $this->app->db->query( "SELECT * FROM categories WHERE category_id = {$categoryId}" );

            if ( !$q11->num_rows ) {
                $this->printError( 500, 1008 );
            }

            $category = $q11->fetch_assoc();
            $q11->free();

            $dt = new \DateTime();

            $dt->setTimestamp( intval( $mainProduct['created'] ) );
            $mainProductCreated = $this->formatDateTimeRepresentation( $dt );

            $dt->setTimestamp( intval( $mainProduct['updated'] ) );
            $mainProductUpdated = $this->formatDateTimeRepresentation( $dt );

            $this->printResponse([
                'mainProductId' => $mainProduct['product_uuid'],
                'categoryId' => $category['category_uuid'],
                'categoryName' => $category['category_name'],
                'mainProductName' => $mainProduct['product_name'],
                'mainProductDescription' => nl2br( $mainProduct['product_description'] ),
                'isRequiredCoverages' => boolval( $mainProduct['is_required_coverages'] ),
                'mainProductCost' => floatval( $mainProduct['cost'] ),
                'created' => $mainProductCreated,
                'updated' => $mainProductUpdated,
                'deleted' => boolval( $mainProduct['deleted'] ),
            ]);
        }
        else {
            $this->printError( 405, 106 );
        }
    }

    public function subProducts() : void {
        $this->checkAccessLevel( anonymousIsAllowed: true );

        $myRole = $this->app->user['role_title'];
        $myUserId = $this->app->user['user_id'];

        $dt = new \DateTime();
        $currentTime = $dt->getTimestamp();

        if ( $this->app->requestMethod === 'GET' ) {
            $subProductUuid = $this->app->db->escape( $this->app->get['subProductId'] ?? "" );
            $mainProductUuid = $this->app->db->escape( $this->app->get['mainProductId'] ?? "" );
            $categoryUuid = $this->app->db->escape( $this->app->get['categoryId'] ?? "" );
            $showDeleted = $myRole === 'admin' ? boolval( $this->app->get['showDeleted'] ?? false ) : false;

            $sqlWhereAndConditionHideDeleted = !$showDeleted ? " AND deleted = 0" : "";
            $sqlWhereConditionHideDeleted = !$showDeleted ? " WHERE deleted = 0" : "";

            $subProductsCount = 0;

            if ( mb_strlen( $subProductUuid ) > 0 ) {
                $q1 = $this->app->db->query( "SELECT * FROM sub_products WHERE product_uuid = \"{$subProductUuid}\"{$sqlWhereAndConditionHideDeleted}" );
                $subProductsCount = 1;
            }
            else if ( mb_strlen( $mainProductUuid ) > 0 ) {
                $q0 = $this->app->db->query( "SELECT main_product_id FROM main_products WHERE product_uuid = \"{$mainProductUuid}\"{$sqlWhereAndConditionHideDeleted}" );

                if ( !$q0->num_rows ) {
                    $this->printError( 404, 1610 );
                }

                $mainProductId = intval( $q0->fetch_assoc()['main_product_id'] );
                $q0->free();

                $q1 = $this->app->db->query( "SELECT * FROM sub_products WHERE main_product_id = {$mainProductId}{$sqlWhereAndConditionHideDeleted}" );
                $subProductsCount = $q1->num_rows;
            }
            else if ( mb_strlen( $categoryUuid ) > 0 ) {
                $offset = intval( $this->app->get['offset'] ?? 0 );
                $limit = intval( $this->app->get['limit'] ?? Settings::PAGINATION_MAX_LIMIT );
                $limit = $limit <= Settings::PAGINATION_MAX_LIMIT ? $limit : Settings::PAGINATION_MAX_LIMIT;

                $q0 = $this->app->db->query( "SELECT category_id FROM categories WHERE category_uuid = \"{$categoryUuid}\"{$sqlWhereAndConditionHideDeleted}" );

                if ( !$q0->num_rows ) {
                    $this->printError( 404, 1510 );
                }
    
                $categoryId = intval( $q0->fetch_assoc()['category_id'] );
                $q0->free();

                $q00 = $this->app->db->query( "SELECT main_product_id FROM main_products WHERE category_id = {$categoryId}{$sqlWhereAndConditionHideDeleted} ORDER BY main_product_id ASC" );

                if ( !$q00->num_rows ) {
                    $this->printError( 404, 1512 );
                }

                $mainProductsIds = [];

                while( $row = $q00->fetch_assoc() ) {
                    $mainProductsIds[] = intval( $row['main_product_id'] );
                }

                $q00->free();

                $mainProductsIds = implode( ',', $mainProductsIds );

                $q1 = $this->app->db->query( "SELECT * FROM sub_products WHERE main_product_id IN ({$mainProductsIds}){$sqlWhereAndConditionHideDeleted} ORDER BY sub_product_id ASC LIMIT {$offset}, {$limit}" );

                $q2 = $this->app->db->query( "SELECT COUNT(*) AS table_rows FROM sub_products WHERE main_product_id IN ($mainProductsIds){$sqlWhereAndConditionHideDeleted}" );

                if ( !$q2->num_rows ) {
                    $subProductsCount = 0;
                }
                else {
                    $subProductsCount = intval( $q2->fetch_assoc()['table_rows'] );
                    $q2->free();
                }
            }
            else {
                $offset = intval( $this->app->get['offset'] ?? 0 );
                $limit = intval( $this->app->get['limit'] ?? Settings::PAGINATION_MAX_LIMIT );
                $limit = $limit <= Settings::PAGINATION_MAX_LIMIT ? $limit : Settings::PAGINATION_MAX_LIMIT;

                $q1 = $this->app->db->query( "SELECT * FROM sub_products{$sqlWhereConditionHideDeleted} ORDER BY sub_product_id ASC LIMIT {$offset}, {$limit}" );

                $q2 = $this->app->db->query( "SELECT COUNT(*) AS table_rows FROM sub_products{$sqlWhereConditionHideDeleted}" );

                if ( !$q2->num_rows ) {
                    $subProductsCount = 0;
                }
                else {
                    $subProductsCount = intval( $q2->fetch_assoc()['table_rows'] );
                    $q2->free();
                }
            }

            if ( !$q1->num_rows ) {
                $this->printError( 404, 161 );
            }

            $subProducts = [];
            $dt = new \DateTime();

            while ( $subProduct = $q1->fetch_assoc() ) {
                $mainProductId = intval( $subProduct['main_product_id'] );

                $dt->setTimestamp( intval( $subProduct['created'] ) );
                $subProductCreated = $this->formatDateTimeRepresentation( $dt );

                $dt->setTimestamp( intval( $subProduct['updated'] ) );
                $subProductUpdated = $this->formatDateTimeRepresentation( $dt );

                $q2 = $this->app->db->query( "SELECT * FROM main_products WHERE main_product_id = {$mainProductId}{$sqlWhereAndConditionHideDeleted}" );

                if ( !$q2->num_rows ) {
                    continue;
                }

                $mainProduct = $q2->fetch_assoc();
                $q2->free();

                $categoryId = intval( $mainProduct['category_id'] );

                $q3 = $this->app->db->query( "SELECT * FROM categories WHERE category_id = {$categoryId}{$sqlWhereAndConditionHideDeleted}" );

                if ( !$q3->num_rows ) {
                    continue;
                }

                $category = $q3->fetch_assoc();
                $q3->free();

                if ( $myRole === 'admin' ) {
                    $subProducts[] = [
                        'subProductId' => $subProduct['product_uuid'],
                        'categoryId' => $category['category_uuid'],
                        'categoryName' => $category['category_name'],
                        'mainProductId' => $mainProduct['product_uuid'],
                        'mainProductName' => $mainProduct['product_name'],
                        'isRequiredCoverages' => boolval( $mainProduct['is_required_coverages'] ),
                        'mainProductCost' => floatval( $mainProduct['cost'] ),
                        'subProductName' => $subProduct['product_name'],
                        'subProductDescription' => nl2br( $subProduct['product_description'] ),
                        'isRequired' => boolval( $subProduct['is_required'] ),
                        'subProductCost' => floatval( $subProduct['cost'] ),
                        'created' => $subProductCreated,
                        'updated' => $subProductUpdated,
                        'deleted' => boolval( $subProduct['deleted'] ),
                    ];
                }
                else {
                    $subProducts[] = [
                        'subProductId' => $subProduct['product_uuid'],
                        'categoryId' => $category['category_uuid'],
                        'categoryName' => $category['category_name'],
                        'mainProductId' => $mainProduct['product_uuid'],
                        'mainProductName' => $mainProduct['product_name'],
                        'isRequiredCoverages' => boolval( $mainProduct['is_required_coverages'] ),
                        'mainProductCost' => floatval( $mainProduct['cost'] ),
                        'subProductName' => $subProduct['product_name'],
                        'subProductDescription' => nl2br( $subProduct['product_description'] ),
                        'isRequired' => boolval( $subProduct['is_required'] ),
                        'subProductCost' => floatval( $subProduct['cost'] ),
                        'created' => $subProductCreated,
                        'updated' => $subProductUpdated,
                        'deleted' => boolval( $subProduct['deleted'] ),
                    ];
                }
            }

            $q1->free();

            $subProducts = [
                "count" => $subProductsCount,
                "subProducts" => $subProducts
            ];

            $this->printResponse( $subProducts );
        }
        else if ( $this->app->requestMethod === 'POST' ) {
            if ( $myRole !== 'admin' ) {
                $this->printError( 403, 103 );
            }

            $data = trim( @file_get_contents('php://input') );
            $data = @json_decode( $data );

            if ( !is_object( $data ) ) {
                $this->printError( 403, 1090 );
            }

            $subProductUuid = $this->app->db->escape( $data->subProductId ?? "" );
            $mainProductUuid = $this->app->db->escape( $data->mainProductId ?? "" );

            $subProductsTableDataset = [];

            $mainProductId = 0;

            if ( mb_strlen( $mainProductUuid ) > 0 ) {
                $q10 = $this->app->db->query( "SELECT main_product_id FROM main_products WHERE product_uuid = \"{$mainProductUuid}\"" );

                if ( !$q10->num_rows ) {
                    $this->printError( 403, 1610 );
                }

                $mainProduct = $q10->fetch_assoc();
                $q10->free();

                $mainProductId = intval( $mainProduct['main_product_id'] );
                
                $subProductsTableDataset['main_product_id'] = $mainProductId;
            }

            if ( !empty( $data->subProductName ) )
                $subProductsTableDataset['product_name'] = $this->app->db->escape( $data->subProductName );

            if ( !empty( $data->subProductDescription ) )
                $subProductsTableDataset['product_description'] = $this->app->db->escape( $data->subProductDescription );

            if ( isset( $data->isRequired ) )
                $subProductsTableDataset['is_required'] = intval( $data->isRequired ) > 0 ? 1 : 0;

            if ( !empty( $data->cost ) )
                $subProductsTableDataset['cost'] = floatval( $data->cost );

            if ( isset( $data->deleted ) )
                $subProductsTableDataset['deleted'] = intval( $data->deleted ) > 0 ? 1 : 0;

            $mode = '';

            if ( mb_strlen( $subProductUuid ) > 0 )
                $mode = 'update';
            else
                $mode = 'create';
            

            if ( $mode === 'create' ) {
                $subProductsTableDataset['product_uuid'] = Utils::generateUUID4();
                $subProductsTableDataset['product_name'] ??= "";
                $subProductsTableDataset['product_description'] ??= "";
                $subProductsTableDataset['is_required'] ??= 0;
                $subProductsTableDataset['cost'] ??= 0.0;
                $subProductsTableDataset['created'] = $currentTime;
                $subProductsTableDataset['updated'] = 0;
                $subProductsTableDataset['deleted'] ??= 0;

                if ( !$mainProductId ) {
                    $this->printError( 403, 1610 );
                }

                if ( empty( $subProductsTableDataset['product_name'] ) || mb_strlen( $subProductsTableDataset['product_name'] ) < 1 ) {
                    $this->printError( 403, 1611 );
                }

                $sqlSliceSubProduct = [];

                foreach( $subProductsTableDataset as $key => $value ) {
                    if ( is_int( $value ) || is_float( $value ) )
                        $sqlSliceSubProduct[] = "{$key} = {$value}";
                    else
                        $sqlSliceSubProduct[] = "{$key} = \"{$value}\"";
                }

                $sqlSliceSubProduct = implode( ", ", $sqlSliceSubProduct );

                $this->app->db->query( "INSERT INTO sub_products SET {$sqlSliceSubProduct}" );
                $subProductId = intval( $this->app->db->insert_id );

                if ( !$subProductId ) {
                    $this->printError( 500, 1010 );
                }

                $actionsTableDataset = [
                    'user_uuid' => $this->app->user['user_uuid'],
                    'username' => $this->app->user['username'],
                    'role' => $this->app->user['role_title'],
                    'to_user_uuid' => '',
                    'to_username' => '',
                    'entity_id' => $subProductId,
                    'action' => 'insert',
                    'fields' => $this->app->db->escape( $sqlSliceSubProduct ),
                    'where_clause' => '',
                    'description' => 'inserted sub product',
                    'created' => $currentTime,
                    'deleted' => 0 
                ];

                $this->setLog( $actionsTableDataset );

                $q10 = $this->app->db->query( "SELECT * FROM sub_products WHERE sub_product_id = {$subProductId}" );
            }
            else if ( $mode === 'update' ) {
                $subProductsTableDataset['updated'] = $currentTime;

                $sqlSliceSubProduct = [];

                foreach( $subProductsTableDataset as $key => $value ) {
                    if ( is_int( $value ) || is_float( $value ) )
                        $sqlSliceSubProduct[] = "{$key} = {$value}";
                    else
                        $sqlSliceSubProduct[] = "{$key} = \"{$value}\"";
                }

                $sqlSliceSubProduct = implode( ", ", $sqlSliceSubProduct );

                $this->app->db->query( "UPDATE sub_products SET {$sqlSliceSubProduct} WHERE product_uuid = \"{$subProductUuid}\"" );

                $actionsTableDataset = [
                    'user_uuid' => $this->app->user['user_uuid'],
                    'username' => $this->app->user['username'],
                    'role' => $this->app->user['role_title'],
                    'to_user_uuid' => '',
                    'to_username' => '',
                    'entity_id' => '',
                    'action' => 'update',
                    'fields' => $this->app->db->escape( $sqlSliceSubProduct ),
                    'where_clause' => $this->app->db->escape( "product_uuid = \"{$subProductUuid}\"" ),
                    'description' => 'updated sub product',
                    'created' => $currentTime,
                    'deleted' => 0 
                ];
    
                $this->setLog( $actionsTableDataset );


                $q10 = $this->app->db->query( "SELECT * FROM sub_products WHERE product_uuid = \"{$subProductUuid}\"" );
            }

            if ( !$q10->num_rows ) {
                $this->printError( 500, 1010 );
            }

            $subProduct = $q10->fetch_assoc();
            $q10->free();

            $mainProductId = intval( $subProduct['main_product_id'] );

            $q11 = $this->app->db->query( "SELECT * FROM main_products WHERE main_product_id = {$mainProductId}" );

            if ( !$q11->num_rows ) {
                $this->printError( 403, 1011 );
            }

            $mainProduct = $q11->fetch_assoc();
            $q11->free();

            $categoryId = intval( $mainProduct['category_id'] );

            $q12 = $this->app->db->query( "SELECT * FROM categories WHERE category_id = {$categoryId}" );

            if ( !$q12->num_rows ) {
                $this->printError( 500, 1008 );
            }

            $category = $q12->fetch_assoc();
            $q12->free();

            $dt = new \DateTime();

            $dt->setTimestamp( intval( $subProduct['created'] ) );
            $subProductCreated = $this->formatDateTimeRepresentation( $dt );

            $dt->setTimestamp( intval( $subProduct['updated'] ) );
            $subProductUpdated = $this->formatDateTimeRepresentation( $dt );

            $this->printResponse([
                'subProductId' => $subProduct['product_uuid'],
                'categoryId' => $category['category_uuid'],
                'categoryName' => $category['category_name'],
                'mainProductId' => $mainProduct['product_uuid'],
                'mainProductName' => $mainProduct['product_name'],
                'isRequiredCoverages' => boolval( $mainProduct['is_required_coverages'] ),
                'mainProductCost' => floatval( $mainProduct['cost'] ),
                'subProductName' => $subProduct['product_name'],
                'subProductDescription' => nl2br( $subProduct['product_description'] ),
                'isRequired' => boolval( $subProduct['is_required'] ),
                'subProductCost' => floatval( $subProduct['cost'] ),
                'created' => $subProductCreated,
                'updated' => $subProductUpdated,
                'deleted' => boolval( $subProduct['deleted'] ),
            ]);
        }
        else {
            $this->printError( 405, 106 );
        }
    }

    public function rating() : void {
        $this->checkAccessLevel( anonymousIsAllowed: false );

        $myRole = $this->app->user['role_title'];
        $myUserId = $this->app->user['user_id'];

        $dt = new \DateTime();
        $currentTime = $dt->getTimestamp();

        if ( $this->app->requestMethod === 'GET' ) {
            $userUuid = $myRole === 'admin' ? $this->app->db->escape( $this->app->get['accountId'] ?? "" ) : $this->app->user['user_uuid'];
            $showDeleted = $myRole === 'admin' ? boolval( $this->app->get['showDeleted'] ?? false ) : false;

            $sqlWhereAndConditionHideDeleted = !$showDeleted ? " AND deleted = 0" : "";
            $sqlWhereConditionHideDeleted = !$showDeleted ? " WHERE deleted = 0" : "";

            $usersCount = 0;
            $usersList = [];
            $rating = [];
            $users = [];

            if ( mb_strlen( $userUuid ) > 0 ) {
                $q1 = $this->app->db->query( "SELECT * FROM users WHERE user_uuid = \"{$userUuid}\"{$sqlWhereAndConditionHideDeleted}" );

                if ( !$q1->num_rows ) {
                    $this->printError( 400, 1810 );
                }

                $users = $q1->fetch_all( MYSQLI_ASSOC );
                $q1->free();

                $usersCount = count( $users );
            }
            else {
                $offset = intval( $this->app->get['offset'] ?? 0 );
                $limit = intval( $this->app->get['limit'] ?? Settings::PAGINATION_MAX_LIMIT );
                $limit = $limit <= Settings::PAGINATION_MAX_LIMIT ? $limit : Settings::PAGINATION_MAX_LIMIT;

                $q0 = $this->app->db->query( "SELECT COUNT(*) AS table_rows FROM users{$sqlWhereConditionHideDeleted}" );

                if ( $q0->num_rows ) {
                    $usersCount = intval( $q0->fetch_assoc()['table_rows'] );
                    $q0->free();
                }
                else {
                    $usersCount = 0;
                }

                $q1 = $this->app->db->query( "SELECT * FROM users{$sqlWhereConditionHideDeleted} ORDER BY user_id ASC LIMIT {$offset}, {$limit}" );

                if ( !$q1->num_rows ) {
                    $this->printError( 400, 1810 );
                }

                $users = $q1->fetch_all( MYSQLI_ASSOC );
                $q1->free();

                $usersCount = count( $users );
            }

            $dt = new \DateTime();

            foreach ( $users as $user ) {
                $userId = intval( $user['user_id'] );
                $ratingId = intval( $user['rating_id'] );

                $currentRating = 0;
                $ratingHistory = [];

                $q3 = $this->app->db->query( "SELECT * FROM rating WHERE user_id = {$userId}{$sqlWhereAndConditionHideDeleted} ORDER BY rating_id DESC" );

                if ( !$q3->num_rows ) {
                    continue;
                }

                for( $i = 0; $ratingRow = $q3->fetch_assoc(); ++$i ) {
                    $dt->setTimestamp( intval( $ratingRow['created'] ) );
                    $ratingCreated = $this->formatDateTimeRepresentation( $dt );

                    if ( $ratingId === intval( $ratingRow['rating_id'] ) ) $currentRating = intval( $ratingRow['rating'] );

                    if ( $myRole === 'admin' ) {
                        $ratingHistory[] = [
                            'ratingId' => $ratingRow['rating_uuid'],
                            'rating' => intval( $ratingRow['rating'] ),
                            'created' => $ratingCreated,
                        ];
                    }
                    else {
                        if ( $myUserId === $userId ) {
                            $ratingHistory[] = [
                                'ratingId' => $ratingRow['rating_uuid'],
                                'rating' => intval( $ratingRow['rating'] ),
                                'created' => $ratingCreated,
                            ];
                        }
                    }
                }

                if ( $myRole === 'admin' ) {
                    $usersList[] = [
                        'accountId' => $user['user_uuid'],
                        'username' => $user['username'],
                        'firstName' => $user['first_name'],
                        'lastName' => $user['last_name'],
                        'currentRating' => $currentRating,
                        'ratingHistory' => $ratingHistory
                    ];
                }
                else {
                    if ( $myUserId === intval( $user['user_id'] ) ) {
                        $usersList[] = [
                            'accountId' => $user['user_uuid'],
                            'username' => $user['username'],
                            'firstName' => $user['first_name'],
                            'lastName' => $user['last_name'],
                            'currentRating' => $currentRating,
                            'ratingHistory' => $ratingHistory
                        ];
                    }
                }

                $q3->free();
            }

            if ( $myRole === 'anonymous' ) {
                $usersCount = 0;
            }

            $rating = [
                "count" => $usersCount,
                "users" => $usersList
            ];

            $this->printResponse( $rating );
        }
        else if ( $this->app->requestMethod === 'POST' ) {
            if ( $myRole !== 'admin' ) {
                $this->printError( 403, 103 );
            }

            $data = trim( @file_get_contents('php://input') );
            $data = @json_decode( $data );

            if ( !is_object( $data ) ) {
                $this->printError( 403, 1090 );
            }

            $newRating = intval( $data->rating ?? 0 );
            $newRating = $newRating >= 0 ? $newRating : 0;

            $userUuid = $myRole === 'admin' ? $this->app->db->escape( $data->accountId ?? $this->app->user['user_uuid'] ) : $this->app->user['user_uuid'];

            $ratingTableDataset = [];

            $user = [];
            $userId = 0;

            $q11 = $this->app->db->query( "SELECT * FROM users WHERE user_uuid = \"{$userUuid}\" AND deleted = 0" );

            if ( $q11->num_rows ) {
                $user = $q11->fetch_assoc();
                $userId = intval( $user['user_id'] );
                $q11->free();
            }
            else {
                $this->printError( 404, 1813 );
            }

            $ratingTableDataset['rating_uuid'] = Utils::generateUUID4();
            $ratingTableDataset['user_id'] = $userId;
            $ratingTableDataset['rating'] = $newRating;
            $ratingTableDataset['created'] = $currentTime;

            $sqlSliceRating = [];

            foreach( $ratingTableDataset as $key => $value ) {
                if ( is_int( $value ) || is_float( $value ) )
                    $sqlSliceRating[] = "{$key} = {$value}";
                else
                    $sqlSliceRating[] = "{$key} = \"{$value}\"";
            }

            $sqlSliceRating = implode( ", ", $sqlSliceRating );

            $this->app->db->query( "INSERT INTO rating SET {$sqlSliceRating}" );
            $ratingId = intval( $this->app->db->insert_id );

            if ( !$ratingId ) {
                $this->printError( 500, 1013 );
            }
            
            $this->app->db->query( "UPDATE users SET rating_id = {$ratingId} WHERE user_id = {$userId}" );

            $actionsTableDataset = [
                'user_uuid' => $this->app->user['user_uuid'],
                'username' => $this->app->user['username'],
                'role' => $this->app->user['role_title'],
                'to_user_uuid' => $userUuid,
                'to_username' => $user['username'],
                'entity_id' => $ratingId,
                'action' => 'update',
                'fields' => $this->app->db->escape( $sqlSliceRating ),
                'where_clause' => "",
                'description' => 'updated account rating',
                'created' => $currentTime,
                'deleted' => 0 
            ];

            $this->setLog( $actionsTableDataset );

            $dt = new \DateTime();

            $dt->setTimestamp( $currentTime );
            $ratingUpdated = $this->formatDateTimeRepresentation( $dt );

            $this->printResponse([
                'accountId' => $user['user_uuid'],
                'username' => $user['username'],
                'firstName' => $user['first_name'],
                'lastName' => $user['last_name'],
                'newRating' => $newRating,
                'updated' => $ratingUpdated,
            ]);
        }
        else {
            $this->printError( 405, 106 );
        }
    }

    public function estimations() : void {
        $this->checkAccessLevel( anonymousIsAllowed: false );

        $myRole = $this->app->user['role_title'];
        $myUserId = $this->app->user['user_id'];

        $dt = new \DateTime();
        $currentTime = $dt->getTimestamp();

        if ( $this->app->requestMethod === 'GET' ) {
            /*if ( $myRole !== 'admin' ) {
                $this->printError( 403, 103 );
            }*/

            $estimationUuid = $this->app->db->escape( $this->app->get['estimationId'] ?? "" );
            $userUuid = $myRole === 'admin' ? $this->app->db->escape( $this->app->get['accountId'] ?? "" ) : $this->app->user['user_uuid'];
            $showDeleted = $myRole === 'admin' ? boolval( $this->app->get['showDeleted'] ?? false ) : false;

            $sqlWhereAndConditionHideDeleted = !$showDeleted ? " AND deleted = 0" : "";
            $sqlWhereConditionHideDeleted = !$showDeleted ? " WHERE deleted = 0" : "";

            $estimationsCount = 0;

            if ( mb_strlen( $estimationUuid ) > 0 ) {
                $q1 = $this->app->db->query( "SELECT * FROM estimations 
                WHERE estimation_uuid = \"{$estimationUuid}\" AND is_used = 0{$sqlWhereAndConditionHideDeleted}" );
                $estimationsCount = 1;
            }
            else if ( mb_strlen( $userUuid ) > 0 ) {
                $offset = intval( $this->app->get['offset'] ?? 0 );
                $limit = intval( $this->app->get['limit'] ?? Settings::PAGINATION_MAX_LIMIT );
                $limit = $limit <= Settings::PAGINATION_MAX_LIMIT ? $limit : Settings::PAGINATION_MAX_LIMIT;

                $createdFrom = intval( $this->app->get['createdFrom'] ?? 0 );
                $createdTo = intval( $this->app->get['createdTo'] ?? ( $currentTime * 1000 ) );

                $createdFrom = intdiv( $createdFrom, 1000 );
                $createdTo = intdiv( $createdTo, 1000 );

                $filterCreated = " AND created >= {$createdFrom} AND created <= {$createdTo}";

                $sqlOrder = $this->app->db->escape( $this->app->get['order'] ?? "" );

                $orderBy = "created DESC";

                if ( $sqlOrder === "asc" ) {
                    $orderBy = "created ASC";
                }
                else if ( $sqlOrder === "desc" ) {
                    $orderBy = "created DESC";
                }

                $q0 = $this->app->db->query( "SELECT user_id FROM users WHERE user_uuid = \"{$userUuid}\"{$sqlWhereAndConditionHideDeleted}" );

                if ( !$q0->num_rows ) {
                    $this->printError( 404, 1910 );
                }
    
                $userId = intval( $q0->fetch_assoc()['user_id'] );
                $q0->free();

                $q1 = $this->app->db->query( "SELECT * FROM estimations 
                WHERE is_used = 0 AND user_id = {$userId}{$filterCreated}{$sqlWhereAndConditionHideDeleted}
                ORDER BY {$orderBy} LIMIT {$offset}, {$limit}" );

                $q2 = $this->app->db->query( "SELECT COUNT(*) AS table_rows FROM estimations 
                WHERE is_used = 0 AND user_id = {$userId}{$filterCreated}{$sqlWhereAndConditionHideDeleted}" );

                if ( !$q2->num_rows ) {
                    $estimationsCount = 0;
                }
                else {
                    $estimationsCount = intval( $q2->fetch_assoc()['table_rows'] );
                    $q2->free();
                }
            }
            else {
                $offset = intval( $this->app->get['offset'] ?? 0 );
                $limit = intval( $this->app->get['limit'] ?? Settings::PAGINATION_MAX_LIMIT );
                $limit = $limit <= Settings::PAGINATION_MAX_LIMIT ? $limit : Settings::PAGINATION_MAX_LIMIT;

                $createdFrom = intval( $this->app->get['createdFrom'] ?? 0 );
                $createdTo = intval( $this->app->get['createdTo'] ?? ( $currentTime * 1000 ) );

                $createdFrom = intdiv( $createdFrom, 1000 );
                $createdTo = intdiv( $createdTo, 1000 );

                $filterCreated = " AND created >= {$createdFrom} AND created <= {$createdTo}";

                $sqlOrder = $this->app->db->escape( $this->app->get['order'] ?? "" );

                $orderBy = "created DESC";
    
                if ( $sqlOrder === "asc" ) {
                    $orderBy = "created ASC";
                }
                else if ( $sqlOrder === "desc" ) {
                    $orderBy = "created DESC";
                }

                $q1 = $this->app->db->query( "SELECT * FROM estimations WHERE is_used = 0{$sqlWhereAndConditionHideDeleted}{$filterCreated} ORDER BY {$orderBy} LIMIT {$offset}, {$limit}" );

                $q2 = $this->app->db->query( "SELECT COUNT(*) AS table_rows FROM estimations WHERE is_used = 0{$sqlWhereAndConditionHideDeleted}{$filterCreated}" );

                if ( !$q2->num_rows ) {
                    $estimationsCount = 0;
                }
                else {
                    $estimationsCount = intval( $q2->fetch_assoc()['table_rows'] );
                    $q2->free();
                }
            }

            if ( !$q1->num_rows ) {
                $this->printError( 404, 191 );
            }

            $estimations = [];
            $dt = new \DateTime();

            while ( $estimation = $q1->fetch_assoc() ) {
                $estimationId = intval( $estimation['estimation_id'] );
                $userId = intval( $estimation['user_id'] );
                $ratingId = intval( $estimation['rating_id'] );
                $vehicleId = intval( $estimation['vehicle_id'] );
                $vehicleDetails = $estimation['vehicle_details'];
                $vehicleRetailValue = intval( $estimation['vehicle_retail_value'] );
                $totalCost = floatval( $estimation['total_cost'] );
                $isUsed = boolval( $estimation['is_used'] );
                $deleted = boolval( $estimation['deleted'] );

                $dt->setTimestamp( intval( $estimation['created'] ) );
                $estimationCreated = $this->formatDateTimeRepresentation( $dt );

                $product = null;
                $subProducts = [];

                $product = @json_decode( $estimation['products'] );
                $mainProductUuid = $this->app->db->escape( $product->mainProductId ?? "" );

                $mainProductName = $product->mainProductName ?? "";
                $mainProductCost = floatval( $product->mainProductCost ?? 0.0 );
                
                if ( 
                    !is_object( $product ) 
                    || empty( $mainProductUuid ) 
                    || !isset( $product->subProducts ) 
                    || !is_array( $product->subProducts ) 
                ) {
                    continue;
                }

                $q6 = $this->app->db->query( "SELECT * FROM main_products WHERE product_uuid = \"{$mainProductUuid}\"" );

                if ( !$q6->num_rows ) continue;

                $mainProduct = $q6->fetch_assoc();
                $q6->free();

                $mainProductId = intval( $mainProduct['main_product_id'] );
                $mainProductIsDeleted = boolval( $mainProduct['deleted'] );

                foreach( $product->subProducts as $i => $subProduct ) {
                    $subProductUuid = $this->app->db->escape( $subProduct->subProductId ?? "" );

                    $q7 = $this->app->db->query( "SELECT * FROM sub_products WHERE product_uuid = \"{$subProductUuid}\"" );

                    if ( !$q7->num_rows ) continue;

                    $subProductRow = $q7->fetch_assoc();
                    $q7->free();

                    $subProductName = $subProduct->subProductName ?? "";
                    $subProductCost = floatval( $subProduct->subProductCost ?? 0.0 );

                    $subProductIsDeleted = boolval( $subProductRow['deleted'] );

                    $subProducts[] = [
                        'subProductId' => $subProductUuid,
                        'subProductName' => $subProductName,
                        'subProductCost' => $subProductCost,
                        'subProductIsDeleted' => $subProductIsDeleted,
                    ];
                }
    
                $categoryId = intval( $mainProduct['category_id'] );
    
                $q2 = $this->app->db->query( "SELECT * FROM categories WHERE category_id = {$categoryId}{$sqlWhereAndConditionHideDeleted}" );
    
                if ( !$q2->num_rows ) {
                    continue;
                }

                $category = $q2->fetch_assoc();
                $q2->free();

                $q3 = $this->app->db->query( "SELECT * FROM users WHERE user_id = {$userId}{$sqlWhereAndConditionHideDeleted}" );
    
                if ( !$q3->num_rows ) {
                    continue;
                }

                $user = $q3->fetch_assoc();
                $q3->free();

                $q4 = $this->app->db->query( "SELECT * FROM rating WHERE rating_id = {$ratingId}{$sqlWhereAndConditionHideDeleted}" );
    
                if ( !$q4->num_rows ) {
                    continue;
                }

                $rating = $q4->fetch_assoc();
                $q4->free();

                $q5 = $this->app->db->query( "SELECT * FROM vehicles WHERE vehicle_id = {$vehicleId}{$sqlWhereAndConditionHideDeleted}" );
    
                if ( !$q5->num_rows ) {
                    continue;
                }

                $vehicle = $q5->fetch_assoc();
                $q5->free();

                $vehicleIsDeleted = boolval( $vehicle['deleted'] );

                $currentDate = new \DateTime( "now", new \DateTimeZone("UTC") );
                $birthDate = \DateTime::createFromFormat( 'U', $user['birth_date'] );
                $birthDateFormatted = $this->formatDateTimeRepresentation( $birthDate );
                $userAge = intval( $currentDate->diff( $birthDate )->format( '%Y' ) );

                $estimations[] = [
                    'estimationId' => $estimation['estimation_uuid'],
                    'accountId' => $user['user_uuid'],
                    'username' => $user['username'],
                    'firstName' => $user['first_name'],
                    'lastName' => $user['last_name'],
                    'birthDate' => intval( $user['birth_date'] ) * 1000,
                    'birthDateFormatted' => $birthDateFormatted,
                    'age' => $userAge,
                    'address' => $user['address'],
                    'email' => $user['email'],
                    'cellphone' => $user['cellphone'],
                    'vehicleId' => $vehicle['vehicle_uuid'],
                    'vehicleDetails' => $vehicleDetails,
                    'vehicleRetailValue' => $vehicleRetailValue,
                    'vehicleIsDeleted' => $vehicleIsDeleted,
                    'categoryId' => $category['category_uuid'],
                    'categoryName' => $category['category_name'],
                    'mainProductId' => $mainProduct['product_uuid'],
                    'mainProductName' => $mainProductName,
                    'mainProductCost' => $mainProductCost,
                    'mainProductIsDeleted' => $mainProductIsDeleted,
                    'subProducts' => $subProducts,
                    'totalCost' => $totalCost,
                    'created' => $estimationCreated,
                    'deleted' => $deleted,
                ];
            }

            $q1->free();

            $estimationsData = [
                "count" => $estimationsCount,
                "estimations" => $estimations
            ];

            $this->printResponse( $estimationsData );
        }
        else if ( $this->app->requestMethod === 'POST' ) {
            $data = trim( @file_get_contents('php://input') );
            $data = @json_decode( $data );

            if ( !is_object( $data ) ) {
                $this->printError( 403, 1090 );
            }

            $userUuid = $myRole === 'admin' ? $this->app->db->escape( $data->accountId ?? $this->app->user['user_uuid'] ) : $this->app->user['user_uuid'];
            $mainProductUuid = $this->app->db->escape( $data->mainProductId ?? "" );
            $subProductsUuids = $data->subProductsIds ?? [];
            $vehicleUuid = $this->app->db->escape( $data->vehicleId ?? "" );

            if ( !is_array( $subProductsUuids ) ) $subProductsUuids = [];

            /*
            Цена машины * rate и делим на 12
            К этой сумме прибавляем цену продукта и субпродуктов
            Пример:
            тачка 100 000 * 0.0199 = 1990
            1990 / 12 = 165.8
            цена продукта и суб 600
            165.8 + 600 = 765.8
            Это число возвращаем
            */

            $productsCost = 0.0;

            $q6 = $this->app->db->query( "SELECT * FROM main_products WHERE product_uuid = \"{$mainProductUuid}\" AND deleted = 0" );

            if ( !$q6->num_rows ) {
                $this->printError( 404, 1911 );
            }

            $mainProduct = $q6->fetch_assoc();
            $q6->free();

            $mainProductId = intval( $mainProduct['main_product_id'] );

            $mainProductCost = floatval( $mainProduct['cost'] );
            $productsCost += $mainProductCost;

            $subProducts = [];

            foreach( $subProductsUuids as $subProductUuid ) {
                $subProductUuid = $this->app->db->escape( $subProductUuid );

                $q7 = $this->app->db->query( "SELECT * FROM sub_products 
                    WHERE product_uuid = \"{$subProductUuid}\" AND main_product_id = {$mainProductId} AND deleted = 0" );

                if ( !$q7->num_rows ) {
                    $this->printError( 404, 1912 );
                }
    
                while( $subProduct = $q7->fetch_assoc() ) {
                    $subProductCost = floatval( $subProduct['cost'] );
                    $productsCost += $subProductCost;

                    $subProducts[] = [
                        'subProductId' => $subProduct['product_uuid'],
                        'subProductName' => $subProduct['product_name'],
                        'subProductCost' => $subProductCost,
                    ];
                }

                $q7->free();
            }

            $q3 = $this->app->db->query( "SELECT * FROM users WHERE user_uuid = \"{$userUuid}\" AND deleted = 0" );
    
            if ( !$q3->num_rows ) {
                $this->printError( 404, 1913 );
            }

            $user = $q3->fetch_assoc();
            $q3->free();

            $userId = intval( $user['user_id'] );
            $ratingId = intval( $user['rating_id'] );

            $currentDate = new \DateTime( "now", new \DateTimeZone("UTC") );
            $birthDate = \DateTime::createFromFormat( 'U', $user['birth_date'] );
            $userAge = intval( $currentDate->diff( $birthDate )->format( '%Y' ) );

            $q4 = $this->app->db->query( "SELECT * FROM rating WHERE rating_id = {$ratingId} AND deleted = 0" );
    
            if ( !$q4->num_rows ) {
                $this->printError( 404, 1914 );
            }

            $rating = $q4->fetch_assoc();
            $q4->free();

            $ratingUuid = $rating['rating_uuid'];

            $q5 = $this->app->db->query( "SELECT * FROM vehicles 
                WHERE vehicle_uuid = \"{$vehicleUuid}\" AND user_id = {$userId} AND deleted = 0" );
    
            if ( !$q5->num_rows ) {
                $this->printError( 404, 1915 );
            }

            $vehicle = $q5->fetch_assoc();
            $q5->free();

            $vehicleId = intval( $vehicle['vehicle_id'] );
            $vehicleRetailValue = intval( $vehicle['retail_value'] );

            if ( $vehicleRetailValue > 1000000 ) $this->printError( 403, 1917 );

            $rate = (function() use( $userAge, $vehicleRetailValue ) : array|bool {
                if ( $userAge < 25 ) {
                    return false;
                }
                else if ( $userAge >= 25 && $userAge <= 45 ) {
                    if ( $vehicleRetailValue <= 100000 ) 
                        return [ 0.0199, "rating_age25-45_price100000" ];
                    else if ( $vehicleRetailValue > 100000 && $vehicleRetailValue <= 350000 ) 
                        return [ 0.0195, "rating_age25-45_price100000-350000" ];
                    else if ( $vehicleRetailValue > 350000 && $vehicleRetailValue <= 700000 ) 
                        return [ 0.0171, "rating_age25-45_price350000-700000" ];
                    else if ( $vehicleRetailValue > 700000 && $vehicleRetailValue <= 1000000 ) 
                        return [ 0.0165, "rating_age25-45_price700000-1000000" ];
                }
                else if ( $userAge > 45 && $userAge < 85 ) {
                    if ( $vehicleRetailValue <= 100000 ) 
                        return [ 0.014, "rating_age45-85_price100000" ];
                    else if ( $vehicleRetailValue > 100000 && $vehicleRetailValue <= 350000 ) 
                        return [ 0.0136, "rating_age45-85_price100000-350000" ];
                    else if ( $vehicleRetailValue > 350000 && $vehicleRetailValue <= 700000 ) 
                        return [ 0.012, "rating_age45-85_price350000-700000" ];
                    else if ( $vehicleRetailValue > 700000 && $vehicleRetailValue <= 1000000 ) 
                        return [ 0.0115, "rating_age45-85_price700000-1000000" ];
                }
                else {
                    return false;
                }
            })();

            if ( !$rate ) {
                $this->printError( 403, 1916 );
            }

            $q11 = $this->app->db->query( "SELECT * FROM resources WHERE r_key = \"{$rate[1]}\"" );

            if ( $q11->num_rows ) {
                $rate = floatval( $q11->fetch_assoc()['r_value'] );
                $q11->free();
            }
            else {
                // default value
                $rate = $rate[0];
            }

            $totalCost = round( $vehicleRetailValue * $rate / 12 + $productsCost, 2 );

            $product = $this->app->db->escape(json_encode([
                'mainProductId' => $mainProduct['product_uuid'],
                'mainProductName' => $mainProduct['product_name'],
                'mainProductCost' => $mainProductCost,
                'subProducts' => $subProducts,
            ], JSON_UNESCAPED_UNICODE));

            

            $estimationTableDataset = [];

            $estimationTableDataset['estimation_uuid'] = Utils::generateUUID4();
            $estimationTableDataset['products'] = $product;
            $estimationTableDataset['user_id'] = $userId;
            $estimationTableDataset['rating_id'] = $ratingId;
            $estimationTableDataset['vehicle_id'] = $vehicleId;
            $estimationTableDataset['vehicle_details'] = $this->app->db->escape( $vehicle['details'] );
            $estimationTableDataset['vehicle_retail_value'] = $vehicleRetailValue;
            $estimationTableDataset['total_cost'] = $totalCost;
            $estimationTableDataset['is_used'] = 0;
            $estimationTableDataset['created'] = $currentTime;
            $estimationTableDataset['deleted'] = 0;

            $sqlSliceEstimation = [];

            foreach( $estimationTableDataset as $key => $value ) {
                if ( is_int( $value ) || is_float( $value ) )
                    $sqlSliceEstimation[] = "{$key} = {$value}";
                else
                    $sqlSliceEstimation[] = "{$key} = \"{$value}\"";
            }

            $sqlSliceEstimation = implode( ", ", $sqlSliceEstimation );

            $this->app->db->query( "INSERT INTO estimations SET {$sqlSliceEstimation}" );
            $estimationId = intval( $this->app->db->insert_id );

            if ( !$estimationId ) {
                $this->printError( 500, 1014 );
            }

            $actionsTableDataset = [
                'user_uuid' => $this->app->user['user_uuid'],
                'username' => $this->app->user['username'],
                'role' => $this->app->user['role_title'],
                'to_user_uuid' => '',
                'to_username' => '',
                'entity_id' => $estimationId,
                'action' => 'insert',
                'fields' => $this->app->db->escape( $sqlSliceEstimation ),
                'where_clause' => '',
                'description' => 'inserted estimation',
                'created' => $currentTime,
                'deleted' => 0 
            ];

            $this->setLog( $actionsTableDataset );

            $dt = new \DateTime();

            $dt->setTimestamp( $currentTime );
            $estimationCreated = $this->formatDateTimeRepresentation( $dt );

            $this->printResponse([
                'estimationId' => $estimationTableDataset['estimation_uuid'],
                'accountId' => $userUuid,
                'vehicleId' => $vehicleUuid,
                'vehicleDetails' => $vehicle['details'],
                'vehicleRetailValue' => $vehicleRetailValue,
                'mainProductId' => $mainProduct['product_uuid'],
                'mainProductName' => $mainProduct['product_name'],
                'mainProductCost' => $mainProductCost,
                'subProducts' => $subProducts,
                'totalCost' => $totalCost,
                'created' => $estimationCreated,
            ]);
        }
        else {
            $this->printError( 405, 106 );
        }
    }

    public function orders() : void {
        $this->checkAccessLevel( anonymousIsAllowed: false );

        $myRole = $this->app->user['role_title'];
        $myUserId = $this->app->user['user_id'];

        $dt = new \DateTime();
        $currentTime = $dt->getTimestamp();

        if ( $this->app->requestMethod === 'GET' ) {
            $orderUuid = $this->app->db->escape( $this->app->get['orderId'] ?? "" );
            $userUuid = $myRole === 'admin' ? $this->app->db->escape( $this->app->get['accountId'] ?? "" ) : $this->app->user['user_uuid'];
            $orderStatus = $this->app->db->escape( $this->app->get['orderStatus'] ?? "" );
            $showDeleted = $myRole === 'admin' ? boolval( $this->app->get['showDeleted'] ?? false ) : false;

            $sqlWhereAndConditionHideDeleted = !$showDeleted ? " AND deleted = 0" : "";
            $sqlJoinWhereAndConditionHideDeleted = !$showDeleted ? " AND o.deleted = 0" : "";
            $sqlWhereConditionHideDeleted = !$showDeleted ? " WHERE deleted = 0" : "";

            $ordersCount = 0;

            if ( mb_strlen( $orderUuid ) > 0 ) {
                $q1 = $this->app->db->query( "SELECT * FROM orders WHERE order_uuid = \"{$orderUuid}\"{$sqlWhereAndConditionHideDeleted}" );
                $ordersCount = 1;
            }
            else if ( mb_strlen( $userUuid ) > 0 ) {
                $offset = intval( $this->app->get['offset'] ?? 0 );
                $limit = intval( $this->app->get['limit'] ?? Settings::PAGINATION_MAX_LIMIT );
                $limit = $limit <= Settings::PAGINATION_MAX_LIMIT ? $limit : Settings::PAGINATION_MAX_LIMIT;

                $sqlOrder = $this->app->db->escape( $this->app->get['order'] ?? "" );

                $orderBy = "o.created DESC";

                if ( $sqlOrder === "asc" ) {
                    $orderBy = "o.created ASC";
                }
                else if ( $sqlOrder === "desc" ) {
                    $orderBy = "o.created DESC";
                }

                $q0 = $this->app->db->query( "SELECT user_id FROM users WHERE user_uuid = \"{$userUuid}\"{$sqlWhereAndConditionHideDeleted}" );

                if ( !$q0->num_rows ) {
                    $this->printError( 404, 2010 );
                }
    
                $userId = intval( $q0->fetch_assoc()['user_id'] );
                $q0->free();

                /*
                $q1 = $this->app->db->query( "SELECT o.*, e.estimation_id, e.user_id  
                    FROM orders o INNER JOIN estimations e 
                    ON o.estimation_id = e.estimation_id 
                    WHERE e.user_id = {$userId}{$sqlJoinWhereAndConditionHideDeleted} 
                    ORDER BY {$orderBy} LIMIT {$offset}, {$limit}" );

                $q2 = $this->app->db->query( "SELECT COUNT(*) as table_rows FROM orders o INNER JOIN estimations e 
                ON o.estimation_id = e.estimation_id WHERE e.user_id = {$userId}{$sqlJoinWhereAndConditionHideDeleted}" );
                */

                $q1 = $this->app->db->query( "SELECT
                    o.*
                    FROM orders o
                    INNER JOIN estimations e
                    INNER JOIN orders_estimations oe
                    ON o.order_id = oe.order_id AND e.estimation_id = oe.estimation_id
                    WHERE e.user_id = {$userId}{$sqlJoinWhereAndConditionHideDeleted}
                    GROUP BY `order_id`
                    ORDER BY {$orderBy} LIMIT {$offset}, {$limit}" );

                $q2 = $this->app->db->query( "SELECT
                    o.order_id
                    FROM orders o
                    INNER JOIN estimations e
                    INNER JOIN orders_estimations oe
                    ON o.order_id = oe.order_id AND e.estimation_id = oe.estimation_id
                    WHERE e.user_id = {$userId}{$sqlJoinWhereAndConditionHideDeleted}
                    GROUP BY `order_id`
                " );

                $q2NumRows = $q2->num_rows;

                if ( !$q2NumRows ) {
                    $ordersCount = 0;
                }
                else {
                    $ordersCount = $q2NumRows;
                    $q2->free();
                }
            }
            else if ( mb_strlen( $orderStatus ) > 0 ) {
                if ( !in_array( needle: $orderStatus, haystack: [ "pending", "approved", "rejected" ], strict: true ) ) {
                    $this->printError( 403, 2013 );
                }

                $offset = intval( $this->app->get['offset'] ?? 0 );
                $limit = intval( $this->app->get['limit'] ?? Settings::PAGINATION_MAX_LIMIT );
                $limit = $limit <= Settings::PAGINATION_MAX_LIMIT ? $limit : Settings::PAGINATION_MAX_LIMIT;

                $sqlOrder = $this->app->db->escape( $this->app->get['order'] ?? "" );

                $orderBy = "created DESC";

                if ( $sqlOrder === "asc" ) {
                    $orderBy = "created ASC";
                }
                else if ( $sqlOrder === "desc" ) {
                    $orderBy = "created DESC";
                }

                $q1 = $this->app->db->query( "SELECT * FROM orders WHERE order_status = \"{$orderStatus}\"{$sqlWhereAndConditionHideDeleted} ORDER BY {$orderBy} LIMIT {$offset}, {$limit}" );

                $q2 = $this->app->db->query( "SELECT COUNT(*) AS table_rows FROM orders WHERE order_status = \"{$orderStatus}\"{$sqlWhereAndConditionHideDeleted}" );

                if ( !$q2->num_rows ) {
                    $ordersCount = 0;
                }
                else {
                    $ordersCount = intval( $q2->fetch_assoc()['table_rows'] );
                    $q2->free();
                }
            }
            else {
                $offset = intval( $this->app->get['offset'] ?? 0 );
                $limit = intval( $this->app->get['limit'] ?? Settings::PAGINATION_MAX_LIMIT );
                $limit = $limit <= Settings::PAGINATION_MAX_LIMIT ? $limit : Settings::PAGINATION_MAX_LIMIT;

                $sqlOrder = $this->app->db->escape( $this->app->get['order'] ?? "" );

                $orderBy = "created DESC";

                if ( $sqlOrder === "asc" ) {
                    $orderBy = "created ASC";
                }
                else if ( $sqlOrder === "desc" ) {
                    $orderBy = "created DESC";
                }

                $q1 = $this->app->db->query( "SELECT * FROM orders{$sqlWhereConditionHideDeleted} ORDER BY {$orderBy} LIMIT {$offset}, {$limit}" );

                $q2 = $this->app->db->query( "SELECT COUNT(*) AS table_rows FROM orders{$sqlWhereConditionHideDeleted}" );

                if ( !$q2->num_rows ) {
                    $ordersCount = 0;
                }
                else {
                    $ordersCount = intval( $q2->fetch_assoc()['table_rows'] );
                    $q2->free();
                }
            }

            if ( !$q1->num_rows ) {
                $this->printError( 404, 201 );
            }

            $orders = [];
            $dt = new \DateTime();

            while ( $order = $q1->fetch_assoc() ) {
                $estimations = [];

                $allEstimationsTotalCost = 0.0;

                $orderId = intval( $order['order_id'] );

                $q00 = $this->app->db->query( "SELECT estimation_id FROM orders_estimations WHERE order_id = {$orderId}" );

                while( $estimationsOrders = $q00->fetch_assoc() ) {
                    $estimationId = intval( $estimationsOrders['estimation_id'] );

                    $q8 = $this->app->db->query( "SELECT * FROM estimations WHERE estimation_id = {$estimationId}" );

                    if ( !$q8->num_rows ) continue;

                    $estimation = $q8->fetch_assoc();
                    $q8->free();

                    $userId = intval( $estimation['user_id'] );

                    if ( $myRole !== 'admin' && $myUserId !== $userId ) continue 2;

                    $ratingId = intval( $estimation['rating_id'] );
                    $vehicleId = intval( $estimation['vehicle_id'] );
                    $vehicleDetails = $estimation['vehicle_details'];
                    $vehicleRetailValue = intval( $estimation['vehicle_retail_value'] );
                    $totalCost = floatval( $estimation['total_cost'] );
                    $estimationIsDeleted = boolval( $estimation['deleted'] );

                    $dt->setTimestamp( intval( $estimation['created'] ) );
                    $estimationCreated = $this->formatDateTimeRepresentation( $dt );

                    $product = null;
                    $subProducts = [];

                    $product = @json_decode( $estimation['products'] );
                    $mainProductUuid = $this->app->db->escape( $product->mainProductId ?? "" );

                    $mainProductName = $product->mainProductName ?? "";
                    $mainProductCost = floatval( $product->mainProductCost ?? 0.0 );
                    
                    if ( 
                        !is_object( $product ) 
                        || empty( $mainProductUuid ) 
                        || !isset( $product->subProducts ) 
                        || !is_array( $product->subProducts ) 
                    ) {
                        continue;
                    }

                    $q6 = $this->app->db->query( "SELECT * FROM main_products WHERE product_uuid = \"{$mainProductUuid}\"" );

                    if ( !$q6->num_rows ) continue;

                    $mainProduct = $q6->fetch_assoc();
                    $q6->free();

                    $mainProductId = intval( $mainProduct['main_product_id'] );
                    $mainProductIsDeleted = boolval( $mainProduct['deleted'] );

                    foreach( $product->subProducts as $i => $subProduct ) {
                        $subProductUuid = $this->app->db->escape( $subProduct->subProductId ?? "" );

                        $q7 = $this->app->db->query( "SELECT * FROM sub_products WHERE product_uuid = \"{$subProductUuid}\"" );

                        if ( !$q7->num_rows ) continue;

                        $subProductRow = $q7->fetch_assoc();
                        $q7->free();

                        $subProductName = $subProduct->subProductName ?? "";
                        $subProductCost = floatval( $subProduct->subProductCost ?? 0.0 );

                        $subProductIsDeleted = boolval( $subProductRow['deleted'] );

                        $subProducts[] = [
                            'subProductId' => $subProductUuid,
                            'subProductName' => $subProductName,
                            'subProductCost' => $subProductCost,
                            'subProductIsDeleted' => $subProductIsDeleted,
                        ];
                    }
        
                    $categoryId = intval( $mainProduct['category_id'] );
        
                    $q2 = $this->app->db->query( "SELECT * FROM categories WHERE category_id = {$categoryId}" );
        
                    if ( !$q2->num_rows ) {
                        continue;
                    }

                    $category = $q2->fetch_assoc();
                    $q2->free();

                    $q3 = $this->app->db->query( "SELECT * FROM users WHERE user_id = {$userId}" );
        
                    if ( !$q3->num_rows ) {
                        continue;
                    }

                    $user = $q3->fetch_assoc();
                    $q3->free();

                    $q4 = $this->app->db->query( "SELECT * FROM rating WHERE rating_id = {$ratingId}" );
        
                    if ( !$q4->num_rows ) {
                        continue;
                    }

                    $rating = $q4->fetch_assoc();
                    $q4->free();

                    $q5 = $this->app->db->query( "SELECT * FROM vehicles WHERE vehicle_id = {$vehicleId}" );
        
                    if ( !$q5->num_rows ) {
                        continue;
                    }

                    $vehicle = $q5->fetch_assoc();
                    $q5->free();

                    $vehicleAssets = [];

                    $q700 = $this->app->db->query( "SELECT * FROM assets WHERE related_to = \"vehicles\" AND relation_uuid = \"{$vehicle['vehicle_uuid']}\"" );

                    while( $asset = $q700->fetch_assoc() ) {
                        $dt->setTimestamp( intval( $asset['created'] ) );
                        $assetCreated = $this->formatDateTimeRepresentation( $dt );

                        if ( $myRole === 'admin' ) {
                            $vehicleAssets[] = [
                                'assetId' => $asset['asset_uuid'],
                                'relatedTo' => $asset['related_to'],
                                'description' => nl2br( $asset['description'] ),
                                'fileType' => $asset['file_type'],
                                'path' => $asset['path'],
                                'created' => $assetCreated,
                                'deleted' => boolval( $asset['deleted'] ),
                            ];
                        }
                        else {
                            $vehicleAssets[] = [
                                'assetId' => $asset['asset_uuid'],
                                'relatedTo' => $asset['related_to'],
                                'description' => nl2br( $asset['description'] ),
                                'fileType' => $asset['file_type'],
                                'path' => $asset['path'],
                            ];
                        }
                    }

                    $q700->free();

                    $vehicleIsDeleted = boolval( $vehicle['deleted'] );

                    $allEstimationsTotalCost += $totalCost;

                    $estimations[] = [
                        'estimationId' => $estimation['estimation_uuid'],
                        'accountId' => $user['user_uuid'],
                        'username' => $user['username'],
                        'firstName' => $user['first_name'],
                        'lastName' => $user['last_name'],
                        'vehicleId' => $vehicle['vehicle_uuid'],
                        'vehicleDetails' => $vehicleDetails,
                        'vehicleRetailValue' => $vehicleRetailValue,
                        'vehicleIsDeleted' => $vehicleIsDeleted,
                        'vehicleAssets' => $vehicleAssets,
                        'categoryId' => $category['category_uuid'],
                        'categoryName' => $category['category_name'],
                        'mainProductId' => $mainProduct['product_uuid'],
                        'mainProductName' => $mainProductName,
                        'mainProductCost' => $mainProductCost,
                        'mainProductIsDeleted' => $mainProductIsDeleted,
                        'subProducts' => $subProducts,
                        'totalCost' => $totalCost,
                        'estimationCreated' => $estimationCreated,
                        'estimationIsDeleted' => $estimationIsDeleted,
                    ];
                }

                $q00->free();

                $adjustedCost = floatval( $order['adjusted_cost'] );
                $orderIsDeleted = boolval( $order['deleted'] );

                $assets = [];

                $q7 = $this->app->db->query( "SELECT * FROM assets WHERE related_to = \"orders\" AND relation_uuid = \"{$order['order_uuid']}\"" );

                while( $asset = $q7->fetch_assoc() ) {
                    $dt->setTimestamp( intval( $asset['created'] ) );
                    $assetCreated = $this->formatDateTimeRepresentation( $dt );

                    if ( $myRole === 'admin' ) {
                        $assets[] = [
                            'assetId' => $asset['asset_uuid'],
                            'relatedTo' => $asset['related_to'],
                            'description' => nl2br( $asset['description'] ),
                            'fileType' => $asset['file_type'],
                            'path' => $asset['path'],
                            'created' => $assetCreated,
                            'deleted' => boolval( $asset['deleted'] ),
                        ];
                    }
                    else {
                        $assets[] = [
                            'assetId' => $asset['asset_uuid'],
                            'relatedTo' => $asset['related_to'],
                            'description' => nl2br( $asset['description'] ),
                            'fileType' => $asset['file_type'],
                            'path' => $asset['path'],
                        ];
                    }
                }

                $q7->free();

                $dt->setTimestamp( intval( $order['created'] ) );
                $orderCreated = $this->formatDateTimeRepresentation( $dt );

                $dt->setTimestamp( intval( $order['updated'] ) );
                $orderUpdated = $this->formatDateTimeRepresentation( $dt );

                $orders[] = [
                    'orderId' => $order['order_uuid'],
                    'orderStatus' => $order['order_status'],
                    'allEstimationsTotalCost' => round( $allEstimationsTotalCost, 2 ),
                    'adjustedCost' => $adjustedCost,
                    'assets' => $assets,
                    'estimations' => $estimations,
                    'orderCreated' => $orderCreated,
                    'orderUpdated' => $orderUpdated,
                    'orderIsDeleted' => $orderIsDeleted,
                ];
            }

            $q1->free();

            $ordersData = [
                "count" => $ordersCount,
                "orders" => $orders
            ];

            $this->printResponse( $ordersData );
        }
        else if ( $this->app->requestMethod === 'POST' ) {
            $data = trim( @file_get_contents('php://input') );
            $data = @json_decode( $data );

            if ( !is_object( $data ) ) {
                $this->printError( 403, 1090 );
            }

            // create order
            $estimationUuids = $data->estimationIds ?? null;
            $userUuid = $myRole === 'admin' ? $this->app->db->escape( $data->accountId ?? $this->app->user['user_uuid'] ) : $this->app->user['user_uuid'];
            // update order
            $orderUuid = $this->app->db->escape( $data->orderId ?? "" );
            $orderStatus = $this->app->db->escape( $data->orderStatus ?? "" );
            $adjustedCost = floatval( $data->adjustedCost ?? -1 );
            $orderDeleted = -1;

            if ( isset( $data->deleted ) )
                $orderDeleted = intval( $data->deleted ) > 0 ? 1 : 0;

            $estimationUuids = !empty( $estimationUuids ) && is_array( $estimationUuids ) ? $estimationUuids : [];

            if ( !empty( $estimationUuids ) ) $mode = 'create';
            else if ( !empty( $orderUuid ) ) $mode = 'update';
            else $this->printError( 404, 2011 );

            if ( $mode === 'create' ) {
                $q6 = $this->app->db->query( "SELECT user_id FROM users WHERE user_uuid = \"{$userUuid}\" AND deleted = 0" );

                if ( !$q6->num_rows ) {
                    $this->printError( 404, 2010 );
                }

                $user = $q6->fetch_assoc();
                $q6->free();

                $userId = intval( $user['user_id'] );

                $estimationUuids = array_slice( $estimationUuids, 0, Settings::MAX_ESTIMATIONS_PER_ORDER );

                $estimationIds = [];

                foreach( $estimationUuids as $estimationUuid ) {
                    if ( $myRole === 'admin' ) {
                        $q7 = $this->app->db->query( "SELECT estimation_id FROM estimations 
                            WHERE estimation_uuid = \"{$estimationUuid}\" AND deleted = 0" );
                    }
                    else {
                        $q7 = $this->app->db->query( "SELECT estimation_id FROM estimations 
                            WHERE estimation_uuid = \"{$estimationUuid}\" AND user_id = {$userId} AND deleted = 0" );
                    }

                    $estimationId = 0;
    
                    if ( !$q7->num_rows ) $this->printError( 404, 2012 );
                    else {
                        $estimationId = intval( $q7->fetch_assoc()['estimation_id'] );
                        $estimationIds[] = $estimationId;
                        $q7->free();
                    }

                    $q8 = $this->app->db->query( "SELECT estimation_id FROM orders_estimations 
                            WHERE estimation_id = {$estimationId}" );

                    if ( $q8->num_rows ) {
                        $q8->free();
                        $this->printError( 404, 2014 );
                    }
                }

                if ( !count( $estimationIds ) ) {
                    $this->printError( 404, 2012 );
                }

                $ordersTableDataset = [];

                $ordersTableDataset['order_uuid'] = Utils::generateUUID4();
                $ordersTableDataset['adjusted_cost'] = 0.00;
                $ordersTableDataset['order_status'] = 'pending';
                $ordersTableDataset['created'] = $currentTime;
                $ordersTableDataset['deleted'] = 0;

                $sqlSliceOrders = [];

                foreach( $ordersTableDataset as $key => $value ) {
                    if ( is_int( $value ) || is_float( $value ) )
                        $sqlSliceOrders[] = "{$key} = {$value}";
                    else
                        $sqlSliceOrders[] = "{$key} = \"{$value}\"";
                }

                $sqlSliceOrders = implode( ", ", $sqlSliceOrders );

                $this->app->db->query( "INSERT INTO orders SET {$sqlSliceOrders}" );
                $orderId = intval( $this->app->db->insert_id );

                if ( !$orderId ) {
                    $this->printError( 500, 1015 );
                }

                $actionsTableDataset = [
                    'user_uuid' => $this->app->user['user_uuid'],
                    'username' => $this->app->user['username'],
                    'role' => $this->app->user['role_title'],
                    'to_user_uuid' => '',
                    'to_username' => '',
                    'entity_id' => $orderId,
                    'action' => 'insert',
                    'fields' => $this->app->db->escape( $sqlSliceOrders ),
                    'where_clause' => '',
                    'description' => 'inserted order',
                    'created' => $currentTime,
                    'deleted' => 0 
                ];
    
                $this->setLog( $actionsTableDataset );

                foreach( $estimationIds as $estimationId ) {
                    $this->app->db->query( "INSERT INTO orders_estimations
                        SET order_id = {$orderId}, estimation_id = {$estimationId}" );

                    $this->app->db->query( "UPDATE estimations
                        SET is_used = 1 WHERE estimation_id = {$estimationId}" );
                }

                $q1 = $this->app->db->query( "SELECT * FROM orders WHERE order_id = {$orderId}" );
            }
            else if ( $mode === 'update' ) {
                $ordersTableDataset = [];

                if ( mb_strlen( $orderStatus ) > 0 && $myRole === 'admin' ) {
                    if ( !in_array( needle: $orderStatus, haystack: [ "pending", "approved", "rejected" ], strict: true ) ) {
                        $this->printError( 403, 2013 );
                    }

                    $ordersTableDataset['order_status'] = $orderStatus;
                }

                if ( $adjustedCost >= 0 && $myRole === 'admin' ) {
                    $ordersTableDataset['adjusted_cost'] = $adjustedCost;
                }

                $ordersTableDataset['updated'] = $currentTime;

                if ( $orderDeleted >= 0 && $myRole === 'admin' ) {
                    $ordersTableDataset['deleted'] = $orderDeleted;
                }

                $sqlSliceOrders = [];

                foreach( $ordersTableDataset as $key => $value ) {
                    if ( is_int( $value ) || is_float( $value ) )
                        $sqlSliceOrders[] = "{$key} = {$value}";
                    else
                        $sqlSliceOrders[] = "{$key} = \"{$value}\"";
                }

                $sqlSliceOrders = implode( ", ", $sqlSliceOrders );

                $this->app->db->query( "UPDATE orders SET {$sqlSliceOrders} WHERE order_uuid = \"{$orderUuid}\"" );

                $actionsTableDataset = [
                    'user_uuid' => $this->app->user['user_uuid'],
                    'username' => $this->app->user['username'],
                    'role' => $this->app->user['role_title'],
                    'to_user_uuid' => '',
                    'to_username' => '',
                    'entity_id' => '',
                    'action' => 'update',
                    'fields' => $this->app->db->escape( $sqlSliceOrders ),
                    'where_clause' => $this->app->db->escape( "order_uuid = \"{$orderUuid}\"" ),
                    'description' => 'updated order',
                    'created' => $currentTime,
                    'deleted' => 0 
                ];
    
                $this->setLog( $actionsTableDataset );

                $q1 = $this->app->db->query( "SELECT * FROM orders WHERE order_uuid = \"{$orderUuid}\"" );
            }

            if ( !$q1->num_rows ) {
                $this->printError( 500, 1015 );
            }

            $order = $q1->fetch_assoc();
            $q1->free();

            $orderId = intval( $order['order_id'] );

            $estimationIds = [];

            $q3 = $this->app->db->query( "SELECT * FROM orders_estimations WHERE order_id = {$orderId}" );

            while( $oe = $q3->fetch_assoc() ) {
                $estimationIds[] = intval( $oe['estimation_id'] );
            }

            $q3->free();

            if ( !count( $estimationIds ) ) {
                $this->printError( 404, 2012 );
            }

            $estimationUuids = [];

            $estimationsIdsSQL = implode( ',', $estimationIds );

            $q2 = $this->app->db->query( "SELECT * FROM estimations 
                WHERE estimation_id IN ({$estimationsIdsSQL}) ORDER BY estimation_id ASC" );

            if ( !$q2->num_rows ) {
                $this->printError( 404, 2012 );
            }

            $userId = 0;

            while( $estimation = $q2->fetch_assoc() ) {
                $estimationUuids[] = $estimation['estimation_uuid'];
                $userId = intval( $estimation['user_id'] );
            }

            $q2->free();

            $q9 = $this->app->db->query( "SELECT * FROM users WHERE user_id = {$userId} AND deleted = 0" );

            if ( !$q9->num_rows ) {
                $this->printError( 404, 2010 );
            }

            $user = $q9->fetch_assoc();
            $q9->free();

            if ( $mode === 'update' && mb_strlen( $orderStatus ) > 0 && $myRole === 'admin' ) {
                $this->sendMail([
                    'to' => $user['email'],
                    'subject' => 'Order status has changed',
                    'body' => "Your order has been <b>{$orderStatus}</b>.<br><br>\n\nThis message is generated automatically. Don't reply it.",
                ]);
            }

            $dt = new \DateTime();

            $dt->setTimestamp( intval( $order['created'] ) );
            $orderCreated = $this->formatDateTimeRepresentation( $dt );

            $dt->setTimestamp( intval( $order['updated'] ) );
            $orderUpdated = $this->formatDateTimeRepresentation( $dt );

            $this->printResponse([
                'orderId' => $order['order_uuid'],
                'estimationIds' => $estimationUuids,
                'adjustedCost' => floatval( $order['adjusted_cost'] ),
                'orderStatus' => $order['order_status'],
                'created' => $orderCreated,
                'updated' => $orderUpdated,
                'deleted' => boolval( $order['deleted'] ),
            ]);
        }
        else {
            $this->printError( 405, 106 );
        }
    }

    public function assets() : void {
        $this->checkAccessLevel( anonymousIsAllowed: false );

        $myRole = $this->app->user['role_title'];
        $myUserId = $this->app->user['user_id'];
        $myUserUuid = $this->app->user['user_uuid'];

        $dt = new \DateTime();
        $currentTime = $dt->getTimestamp();

        if ( $this->app->requestMethod === 'GET' ) {
            $filter = $this->app->db->escape( $this->app->get['fileType'] ?? "" );
            $userUuid = $myRole === 'admin' ? $this->app->db->escape( $this->app->get['accountId'] ?? "" ) : $this->app->user['user_uuid'];
            $showDeleted = $myRole === 'admin' ? boolval( $this->app->get['showDeleted'] ?? false ) : false;

            $sqlWhereAndConditionHideDeleted = !$showDeleted ? " AND deleted = 0" : "";
            $sqlWhereConditionHideDeleted = !$showDeleted ? " WHERE deleted = 0" : "";

            $assetsCount = 0;

            $sqlWhereAndConditionFilter = "";
            $sqlWhereConditionFilter = "";

            if ( mb_strlen( $filter ) > 0 ) {
                $sqlWhereAndConditionFilter = " AND file_type = \"{$filter}\"";
                $sqlWhereConditionFilter = " WHERE file_type = \"{$filter}\"";
            }

            $offset = intval( $this->app->get['offset'] ?? 0 );
            $limit = intval( $this->app->get['limit'] ?? Settings::PAGINATION_MAX_LIMIT );
            $limit = $limit <= Settings::PAGINATION_MAX_LIMIT ? $limit : Settings::PAGINATION_MAX_LIMIT;

            if ( mb_strlen( $userUuid ) > 0 ) {
                $q0 = $this->app->db->query( "SELECT user_id FROM users WHERE user_uuid = \"{$userUuid}\"{$sqlWhereAndConditionHideDeleted}" );

                if ( !$q0->num_rows ) {
                    $this->printError( 404, 2110 );
                }

                $userId = intval( $q0->fetch_assoc()['user_id'] );

                $q0->free();

                $q1 = $this->app->db->query( "SELECT * FROM assets WHERE user_id = {$userId}{$sqlWhereAndConditionFilter}{$sqlWhereAndConditionHideDeleted} ORDER BY asset_id DESC LIMIT {$offset}, {$limit}" );

                $q2 = $this->app->db->query( "SELECT COUNT(*) AS table_rows FROM assets WHERE user_id = {$userId}{$sqlWhereAndConditionFilter}{$sqlWhereAndConditionHideDeleted}" );

                if ( !$q2->num_rows ) {
                    $assetsCount = 0;
                }
                else {
                    $assetsCount = intval( $q2->fetch_assoc()['table_rows'] );
                    $q2->free();
                }
            }
            else {
                $q1 = $this->app->db->query( "SELECT * FROM assets WHERE user_id > 0{$sqlWhereAndConditionFilter}{$sqlWhereAndConditionHideDeleted} ORDER BY asset_id DESC LIMIT {$offset}, {$limit}" );

                $q2 = $this->app->db->query( "SELECT COUNT(*) AS table_rows FROM assets WHERE user_id > 0{$sqlWhereAndConditionFilter}{$sqlWhereAndConditionHideDeleted}" );

                if ( !$q2->num_rows ) {
                    $assetsCount = 0;
                }
                else {
                    $assetsCount = intval( $q2->fetch_assoc()['table_rows'] );
                    $q2->free();
                }
            }

            if ( !$q1->num_rows ) {
                $this->printError( 404, 211 );
            }

            $assets = [];
            $dt = new \DateTime();

            while( $asset = $q1->fetch_assoc() ) {
                $userId = intval( $asset['user_id'] );

                $q3 = $this->app->db->query( "SELECT * FROM users WHERE user_id = {$userId}{$sqlWhereAndConditionHideDeleted}" );

                if ( !$q3->num_rows ) {
                    continue;
                }

                $user = $q3->fetch_assoc();
                $q3->free();

                $dt->setTimestamp( intval( $asset['created'] ) );
                $assetCreated = $this->formatDateTimeRepresentation( $dt );

                if ( $myRole === 'admin' ) {
                    $assets[] = [
                        'assetId' => $asset['asset_uuid'],
                        'accountId' => $user['user_uuid'],
                        'username' => $user['username'],
                        'firstName' => $user['first_name'],
                        'lastName' => $user['last_name'],
                        'relatedTo' => $asset['related_to'],
                        'relationId' => $asset['relation_uuid'],
                        'description' => nl2br( $asset['description'] ),
                        'fileType' => $asset['file_type'],
                        'path' => $asset['path'],
                        'created' => $assetCreated,
                        'deleted' => boolval( $asset['deleted'] ),
                    ];
                }
                else {
                    $assets[] = [
                        'assetId' => $asset['asset_uuid'],
                        'accountId' => $user['user_uuid'],
                        'username' => $user['username'],
                        'firstName' => $user['first_name'],
                        'lastName' => $user['last_name'],
                        'relatedTo' => $asset['related_to'],
                        'relationId' => $asset['relation_uuid'],
                        'description' => nl2br( $asset['description'] ),
                        'fileType' => $asset['file_type'],
                        'path' => $asset['path'],
                    ];
                }
            }

            $q1->free();

            $assets = [
                "count" => $assetsCount,
                "assets" => $assets
            ];

            $this->printResponse( $assets );
        }
        else if ( $this->app->requestMethod === 'POST' ) {
            $this->app->get['act'] ??= "";

            if ( $this->app->get['act'] === 'upload' ) {
                if ( empty( $this->app->files['asset']['tmp_name'] ) ) {
                    $this->printError( 403, 2111 );
                }

                if ( !is_array( $this->app->files['asset']['tmp_name'] ) ) {
                    $this->deleteUploadedFiles( $this->app->files['asset']['tmp_name'] );
                    $this->printError( 403, 2125 );
                }

                if ( count( $this->app->files['asset']['tmp_name'] ) > Settings::MAX_UPLOADS_PER_ONCE ) {
                    $this->deleteUploadedFiles( $this->app->files['asset']['tmp_name'] );
                    $this->printError( 403, 2124 );
                }

                $data = $this->app->post['meta'] ?? null;
                $data = @json_decode( $data );

                if ( !is_object( $data ) ) {
                    $this->deleteUploadedFiles( $this->app->files['asset']['tmp_name'] );
                    $this->printError( 403, 1090 );
                }

                // meta
                $fileType = $this->app->db->escape( $data->fileType ?? "" );
                $description = $this->app->db->escape( strip_tags( $data->description ?? "" ) );
                $relatedTo = $this->app->db->escape( $data->relatedTo ?? "" );
                $relationId = $this->app->db->escape( $data->relationId ?? "" );

                $userUuid = $this->app->user['user_uuid'];
                $userFolder = $this->app->assetsDir . "/{$userUuid}";
                $userFolderFullPath = $this->app->docDir . $userFolder;

                $q0 = $this->app->db->query( "SELECT user_id FROM users WHERE user_uuid = \"{$userUuid}\" AND deleted = 0" );

                if ( !$q0->num_rows ) {
                    $this->deleteUploadedFiles( $this->app->files['asset']['tmp_name'] );
                    $this->printError( 404, 2110 );
                }

                $userId = intval( $q0->fetch_assoc()['user_id'] );

                $q0->free();

                $dt = new \DateTime();

                $dt->sub( new \DateInterval( Settings::UPLOAD_INTERVAL ) );
                $stopTime = $dt->getTimestamp();

                $q1 = $this->app->db->query( "SELECT asset_id FROM assets WHERE user_id = {$userId} AND created >= {$stopTime}" );

                $uploadedFilesPerUploadInterval = $q1->num_rows;
                $q1->free();

                if ( $uploadedFilesPerUploadInterval >= Settings::MAX_UPLOADS_PER_UPLOAD_INTERVAL ) {
                    $this->deleteUploadedFiles( $this->app->files['asset']['tmp_name'] );
                    $this->printError( 403, 2119 );
                }

                if ( !$fileType ) {
                    $this->deleteUploadedFiles( $this->app->files['asset']['tmp_name'] );
                    $this->printError( 403, 2112 );
                }

                if ( !in_array( needle: $fileType, haystack: [ "avatar", "photo", "document" ], strict: true ) ) {
                    $this->deleteUploadedFiles( $this->app->files['asset']['tmp_name'] );
                    $this->printError( 403, 2112 );
                }

                if ( mb_strlen( $relatedTo ) > 0 ) {
                    if ( !in_array( needle: $relatedTo, haystack: [ "orders", "vehicles", "avatar", "driverLicensePhoto" ], strict: true ) ) {
                        $this->deleteUploadedFiles( $this->app->files['asset']['tmp_name'] );
                        $this->printError( 403, 2121 );
                    }

                    if ( $relatedTo === "avatar" ) {
                        if ( $fileType !== "avatar" ) {
                            $this->deleteUploadedFiles( $this->app->files['asset']['tmp_name'] );
                            $this->printError( 403, 2126 );
                        }

                        if ( $relationId !== $userUuid ) {
                            $this->deleteUploadedFiles( $this->app->files['asset']['tmp_name'] );
                            $this->printError( 403, 2128 );
                        }

                        if ( count( $this->app->files['asset']['tmp_name'] ) > 1 ) {
                            $this->deleteUploadedFiles( $this->app->files['asset']['tmp_name'] );
                            $this->printError( 403, 2127 );
                        }
                    }

                    if ( $relatedTo === "driverLicensePhoto" ) {
                        if ( $fileType !== "photo" ) {
                            $this->deleteUploadedFiles( $this->app->files['asset']['tmp_name'] );
                            $this->printError( 403, 2129 );
                        }

                        if ( $relationId !== $userUuid ) {
                            $this->deleteUploadedFiles( $this->app->files['asset']['tmp_name'] );
                            $this->printError( 403, 2131 );
                        }

                        if ( count( $this->app->files['asset']['tmp_name'] ) > 1 ) {
                            $this->deleteUploadedFiles( $this->app->files['asset']['tmp_name'] );
                            $this->printError( 403, 2130 );
                        }
                    }

                    if ( $relatedTo === "orders" ) {
                        if ( $fileType !== "photo" && $fileType !== "document" ) {
                            $this->deleteUploadedFiles( $this->app->files['asset']['tmp_name'] );
                            $this->printError( 403, 2135 );
                        }

                        $q3 = $this->app->db->query( "SELECT * FROM orders WHERE order_uuid = \"{$relationId}\" AND deleted = 0" );

                        if ( !$q3->num_rows ) {
                            $this->deleteUploadedFiles( $this->app->files['asset']['tmp_name'] );
                            $this->printError( 403, 2122 );
                        }

                        $order = $q3->fetch_assoc();
                        $q3->free();

                        if ( $order['order_status'] === 'rejected' ) {
                            $this->deleteUploadedFiles( $this->app->files['asset']['tmp_name'] );
                            $this->printError( 403, 2123 );
                        }
                    }

                    if ( $relatedTo === "vehicles" ) {
                        if ( $fileType !== "photo" ) {
                            $this->deleteUploadedFiles( $this->app->files['asset']['tmp_name'] );
                            $this->printError( 403, 2134 );
                        }

                        $q3 = $this->app->db->query( "SELECT * FROM vehicles WHERE vehicle_uuid = \"{$relationId}\" AND deleted = 0" );

                        if ( !$q3->num_rows ) {
                            $this->deleteUploadedFiles( $this->app->files['asset']['tmp_name'] );
                            $this->printError( 403, 2133 );
                        }

                        $vehicle = $q3->fetch_assoc();
                        $q3->free();
                    }
                }

                $uploadedFiles = [];

                if ( !file_exists( $userFolderFullPath ) ) {
                    $cfState = @mkdir( directory : $userFolderFullPath, recursive : true );
        
                    if ( !$cfState ) {
                        $this->deleteUploadedFiles( $this->app->files['asset']['tmp_name'] );
                        $this->printError( 500, 1016 );
                    }
                }

                foreach( $this->app->files['asset']['tmp_name'] as $fileIndex => $filename ) {
                    if ( $this->app->files['asset']['error'][ $fileIndex ] !== UPLOAD_ERR_OK ) {
                        //$this->deleteUploadedFiles( $this->app->files['asset']['tmp_name'] );
                        //$this->printError( 500, 2113 );
                        $this->deleteUploadedFiles( $filename );
                        continue;
                    }
    
                    if ( $this->app->files['asset']['size'][ $fileIndex ] > Settings::UPLOAD_MAX_FILESIZE ) {
                        //$this->deleteUploadedFiles( $this->app->files['asset']['tmp_name'] );
                        //$this->printError( 403, 2120 );
                        $this->deleteUploadedFiles( $filename );
                        continue;
                    }
    
                    $detectedMime = @mime_content_type( $filename );
    
                    if ( in_array( needle: $fileType, haystack: [ "avatar", "photo" ], strict: true )
                        && !in_array( needle: $detectedMime, haystack: [ 
                            "image/pjpeg",
                            "image/jpeg", 
                            "image/png", 
                        ], strict: true )
                    ) {
                        //$this->deleteUploadedFiles( $this->app->files['asset']['tmp_name'] );
                        //$this->printError( 403, 2114 );
                        $this->deleteUploadedFiles( $filename );
                        continue;
                    }
    
                    if ( $fileType === "document" && $detectedMime !== "application/pdf" ) {
                        //$this->deleteUploadedFiles( $this->app->files['asset']['tmp_name'] );
                        //$this->printError( 403, 2114 );
                        $this->deleteUploadedFiles( $filename );
                        continue;
                    }

                    if ( $fileType === "avatar" || $fileType === "photo" ) {
                        $imageSize = @getimagesize( $filename );

                        $width = $imageSize[0] ?? 0;
                        $height = $imageSize[1] ?? 0;

                        if ( $fileType === "avatar" ) {
                            if ( ( $width < 50 || $width > 300 ) || ( $height < 50 || $height > 300 ) ) {
                                $this->deleteUploadedFiles( $filename );
                                $this->printError( 403, 2132 );
                            }
                        }
                        else if ( $fileType === "photo" ) {
                            if ( ( $width < 100 || $width > 10000 ) || ( $height < 100 || $height > 10000 ) ) {
                                $this->deleteUploadedFiles( $filename );
                                continue;
                            }
                        }
                    }
    
                    $newFileName = basename( $this->app->files['asset']['name'][ $fileIndex ] );
                    $ext = mb_strrchr( $newFileName, '.' ) ?: ".000";
                    $newFileName = md5( $newFileName . random_bytes(16) ) . $ext;
    
                    $fileHash = hash_file( 'md5', $filename );
    
                    $q2 = $this->app->db->query( "SELECT * FROM assets WHERE file_hash = \"{$fileHash}\" AND user_id = {$userId}" );
    
                    if ( $q2->num_rows ) {
                        /*
                        $this->deleteUploadedFiles( $this->app->files['asset']['tmp_name'] );
                        $this->printError( 403, 2118 );
                        */
                    }
    
                    $q2->free();
    
                    $userFilePath = $this->app->db->escape( $userFolder . "/{$newFileName}" );
    
                    if ( !move_uploaded_file( $filename, $userFolderFullPath . "/{$newFileName}" ) ) {
                        //$this->deleteUploadedFiles( $this->app->files['asset']['tmp_name'] );
                        //$this->printError( 403, 2115 );
                        $this->deleteUploadedFiles( $filename );
                        continue;
                    }
    
                    $assetsTableDataset = [];
    
                    $assetsTableDataset['asset_uuid'] = Utils::generateUUID4();
                    $assetsTableDataset['user_id'] = $userId;
                    $assetsTableDataset['related_to'] = $relatedTo;
                    $assetsTableDataset['relation_uuid'] = $relationId;
                    $assetsTableDataset['description'] = $description;
                    $assetsTableDataset['file_type'] = $fileType;
                    $assetsTableDataset['file_hash'] = $fileHash;
                    $assetsTableDataset['path'] = $userFilePath;
                    $assetsTableDataset['created'] = $currentTime;
                    $assetsTableDataset['deleted'] = 0;
    
                    $sqlSliceAssets = [];
    
                    foreach( $assetsTableDataset as $key => $value ) {
                        if ( is_int( $value ) || is_float( $value ) )
                            $sqlSliceAssets[] = "{$key} = {$value}";
                        else
                            $sqlSliceAssets[] = "{$key} = \"{$value}\"";
                    }
    
                    $sqlSliceAssets = implode( ", ", $sqlSliceAssets );
    
                    $this->app->db->query( "INSERT INTO assets SET {$sqlSliceAssets}" );
                    $assetId = intval( $this->app->db->insert_id );
    
                    if ( !$assetId ) {
                        $this->printError( 500, 1017 );
                    }

                    $actionsTableDataset = [
                        'user_uuid' => $this->app->user['user_uuid'],
                        'username' => $this->app->user['username'],
                        'role' => $this->app->user['role_title'],
                        'to_user_uuid' => '',
                        'to_username' => '',
                        'entity_id' => $assetId,
                        'action' => 'insert',
                        'fields' => $this->app->db->escape( $sqlSliceAssets ),
                        'where_clause' => '',
                        'description' => 'inserted asset',
                        'created' => $currentTime,
                        'deleted' => 0 
                    ];
        
                    $this->setLog( $actionsTableDataset );

                    if ( $relatedTo === "avatar" ) {
                        $this->app->db->query( "UPDATE users SET avatar = \"{$userFilePath}\" WHERE user_id = {$userId}" );
                    }

                    if ( $relatedTo === "driverLicensePhoto" ) {
                        $this->app->db->query( "UPDATE users SET driver_license_photo = \"{$userFilePath}\" WHERE user_id = {$userId}" );
                    }
    
                    $dt->setTimestamp( intval( $currentTime ) );
                    $assetCreated = $this->formatDateTimeRepresentation( $dt );

                    $uploadedFiles[] = [
                        'assetId' => $assetsTableDataset['asset_uuid'],
                        'accountId' => $userUuid,
                        'relatedTo' => $assetsTableDataset['related_to'],
                        'relationId' => $assetsTableDataset['relation_uuid'],
                        'description' => nl2br( $description ),
                        'fileType' => $fileType,
                        'path' => $userFilePath,
                        'created' => $assetCreated,
                        'deleted' => false,
                    ];
                }

                $uploadedFiles = [
                    "count" => count( $uploadedFiles ),
                    "assets" => $uploadedFiles
                ];

                $this->printResponse( $uploadedFiles );
            }
            else if ( $this->app->get['act'] === 'remove' ) {
                $data = trim( @file_get_contents('php://input') );
                $data = @json_decode( $data );

                if ( !is_object( $data ) ) {
                    $this->printError( 403, 1090 );
                }

                $assetUuid = $this->app->db->escape( $data->assetId ?? "" );
                $userUuid = $myRole === 'admin' ? $this->app->db->escape( $data->accountId ?? $this->app->user['user_uuid'] ) : $this->app->user['user_uuid'];

                if ( $myRole === 'admin' ) {
                    $q1 = $this->app->db->query( "SELECT asset_id FROM assets WHERE asset_uuid = \"{$assetUuid}\"" );

                    if ( !$q1->num_rows ) {
                        $this->printError( 404, 2117 );
                    }

                    $q1->free();
                }
                else {
                    $q0 = $this->app->db->query( "SELECT user_id FROM users WHERE user_uuid = \"{$userUuid}\" AND deleted = 0" );

                    if ( !$q0->num_rows ) {
                        $this->printError( 404, 2110 );
                    }

                    $userId = intval( $q0->fetch_assoc()['user_id'] );

                    $q0->free();

                    $q1 = $this->app->db->query( "SELECT asset_id FROM assets WHERE user_id = {$userId} AND asset_uuid = \"{$assetUuid}\"" );

                    if ( !$q1->num_rows ) {
                        $this->printError( 404, 2117 );
                    }

                    $q1->free();
                }

                $this->app->db->query( "UPDATE assets SET deleted = 1 WHERE asset_uuid = \"{$assetUuid}\"" );

                $actionsTableDataset = [
                    'user_uuid' => $this->app->user['user_uuid'],
                    'username' => $this->app->user['username'],
                    'role' => $this->app->user['role_title'],
                    'to_user_uuid' => '',
                    'to_username' => '',
                    'action' => 'update',
                    'fields' => 'deleted = 1',
                    'where_clause' => $this->app->db->escape( "asset_uuid = \"{$assetUuid}\"" ),
                    'description' => 'updated asset',
                    'created' => $currentTime,
                    'deleted' => 0 
                ];
    
                $this->setLog( $actionsTableDataset );

                $this->printResponse([
                    'assetId' => $assetUuid,
                    'accountId' => $userUuid,
                    'deleted' => true,
                ]);

            }
            else {
                $this->printError( 403, 2116 );
            }
        }
        else {
            $this->printError( 405, 106 );
        }
    }

    public function users() : void {
        $this->checkAccessLevel( anonymousIsAllowed: true );

        $myRole = $this->app->user['role_title'];
        $myUserId = $this->app->user['user_id'];

        $dt = new \DateTime();
        $currentTime = $dt->getTimestamp();

        if ( $this->app->requestMethod === 'GET' ) {
            $userUuid = $this->app->db->escape( $this->app->get['accountId'] ?? "" );
            $username = $this->app->db->escape( $this->app->get['username'] ?? "" );
            $firstName = $this->app->db->escape( $this->app->get['firstName'] ?? "" );
            $lastName = $this->app->db->escape( $this->app->get['lastName'] ?? "" );
            $clientIdNumber = $this->app->db->escape( $this->app->get['clientIdNumber'] ?? "" );
            $cellphone = $this->app->db->escape( $this->app->get['cellphone'] ?? "" );
            $email = $this->app->db->escape( $this->app->get['email'] ?? "" );
            $role = $this->app->db->escape( $this->app->get['role'] ?? "" );
            $showDeleted = $myRole === 'admin' ? boolval( $this->app->get['showDeleted'] ?? false ) : false;

            $sqlWhereAndConditionHideDeleted = !$showDeleted ? " AND deleted = 0" : "";
            $sqlWhereConditionHideDeleted = !$showDeleted ? " WHERE deleted = 0" : "";

            $usersCount = 0;

            $roleIsSpecified = in_array( needle : $role, haystack : [ "user", "admin" ], strict : true );

            if ( mb_strlen( $userUuid ) > 0 ) {
                $q1 = $this->app->db->query( "SELECT * FROM users WHERE user_uuid = \"{$userUuid}\"{$sqlWhereAndConditionHideDeleted}" );
                $usersCount = 1;
            }
            else if ( 
                mb_strlen( $username ) > 0 
                || mb_strlen( $firstName ) > 0 
                || mb_strlen( $lastName ) > 0 
                || mb_strlen( $clientIdNumber ) > 0
                || mb_strlen( $cellphone ) > 0
                || mb_strlen( $email ) > 0
                || $roleIsSpecified
            ) {
                $sqlFilter = $this->app->db->escape( $this->app->get['filter'] ?? "" );
                $sqlOrder = $this->app->db->escape( $this->app->get['order'] ?? "" );
                $offset = intval( $this->app->get['offset'] ?? 0 );
                $limit = intval( $this->app->get['limit'] ?? Settings::PAGINATION_MAX_LIMIT );
                $limit = $limit <= Settings::PAGINATION_MAX_LIMIT ? $limit : Settings::PAGINATION_MAX_LIMIT;

                // by default
                $searchField = "username";
                $searchValue = "";

                if ( mb_strlen( $username ) > 0 ) {
                    $searchField = "username";
                    $searchValue = $username;
                }
                else if ( mb_strlen( $firstName ) > 0 ) {
                    $searchField = "first_name";
                    $searchValue = $firstName;
                }
                else if ( mb_strlen( $lastName ) > 0 ) {
                    $searchField = "last_name";
                    $searchValue = $lastName;
                }
                else if ( mb_strlen( $clientIdNumber ) > 0 ) {
                    $searchField = "client_id";
                    $searchValue = $clientIdNumber;
                }
                else if ( mb_strlen( $cellphone ) > 0 ) {
                    $searchField = "cellphone";
                    $searchValue = $cellphone;
                }
                else if ( mb_strlen( $email ) > 0 ) {
                    $searchField = "email";
                    $searchValue = $email;
                }

                $orderBy = " ORDER BY user_id ASC";

                if ( $sqlOrder === "asc" ) {
                    $orderBy = " ORDER BY created ASC";
                }
                else if ( $sqlOrder === "desc" ) {
                    $orderBy = " ORDER BY created DESC";
                }

                if ( $sqlFilter === "startsWith" ) {
                    $q1Where = "{roleFilter}{createdFilter}{$searchField} LIKE \"{$searchValue}%\"{$sqlWhereAndConditionHideDeleted}{$orderBy} LIMIT {$offset}, {$limit}";
                    $q2Where = "{roleFilter}{createdFilter}{$searchField} LIKE \"{$searchValue}%\" {$sqlWhereAndConditionHideDeleted}";
                }
                else if ( $sqlFilter === "endsWith" ) {
                    $q1Where = "{roleFilter}{createdFilter}{$searchField} LIKE \"%{$searchValue}\"{$sqlWhereAndConditionHideDeleted}{$orderBy} LIMIT {$offset}, {$limit}";
                    $q2Where = "{roleFilter}{createdFilter}{$searchField} LIKE \"%{$searchValue}\"{$sqlWhereAndConditionHideDeleted}";
                }
                else if ( $sqlFilter === "contains" ) {
                    $q1Where = "{roleFilter}{createdFilter}{$searchField} LIKE \"%{$searchValue}%\"{$sqlWhereAndConditionHideDeleted}{$orderBy} LIMIT {$offset}, {$limit}";
                    $q2Where = "{roleFilter}{createdFilter}{$searchField} LIKE \"%{$searchValue}%\"{$sqlWhereAndConditionHideDeleted}";
                }
                else {
                    $q1Where = "{roleFilter}{createdFilter}{$searchField} = \"{$searchValue}\"{$sqlWhereAndConditionHideDeleted}";
                    $q2Where = "{roleFilter}{createdFilter}{$searchField} = \"{$searchValue}\"{$sqlWhereAndConditionHideDeleted}";
                }

                $roleFilter = "";

                if ( $roleIsSpecified ) {
                    $q3 = $this->app->db->query( "SELECT role_id FROM roles WHERE role = \"{$role}\"" );

                    if ( !$q3->num_rows ) {
                        $this->printError( 403, 1316 );
                    }

                    $roleId = intval( $q3->fetch_assoc()['role_id'] );
                    $q3->free();

                    $roleFilter = " role_id = {$roleId} AND ";
                }

                $q1Where = str_replace( "{roleFilter}", $roleFilter, $q1Where );
                $q2Where = str_replace( "{roleFilter}", $roleFilter, $q2Where );

                $createdFrom = intval( $this->app->get['createdFrom'] ?? 0 );
                $createdTo = intval( $this->app->get['createdTo'] ?? ( $currentTime * 1000 ) );

                $filterCreated = "";

                $createdFrom = intdiv( $createdFrom, 1000 );
                $createdTo = intdiv( $createdTo, 1000 );

                $filterCreated = " created >= {$createdFrom} AND created <= {$createdTo} AND ";

                $q1Where = str_replace( "{createdFilter}", $filterCreated, $q1Where );
                $q2Where = str_replace( "{createdFilter}", $filterCreated, $q2Where );

                $q1 = $this->app->db->query( "SELECT * FROM users WHERE{$q1Where}" );
                $q2 = $this->app->db->query( "SELECT COUNT(*) AS table_rows FROM users WHERE{$q2Where}" );

                if ( !$q2->num_rows ) {
                    $usersCount = 0;
                }
                else {
                    $usersCount = intval( $q2->fetch_assoc()['table_rows'] );
                    $q2->free();
                }
            }
            else {
                $offset = intval( $this->app->get['offset'] ?? 0 );
                $limit = intval( $this->app->get['limit'] ?? Settings::PAGINATION_MAX_LIMIT );
                $limit = $limit <= Settings::PAGINATION_MAX_LIMIT ? $limit : Settings::PAGINATION_MAX_LIMIT;

                $sqlOrder = $this->app->db->escape( $this->app->get['order'] ?? "" );

                $orderBy = "created ASC";

                if ( $sqlOrder === "asc" ) {
                    $orderBy = "created ASC";
                }
                else if ( $sqlOrder === "desc" ) {
                    $orderBy = "created DESC";
                }

                $createdFrom = intval( $this->app->get['createdFrom'] ?? 0 );
                $createdTo = intval( $this->app->get['createdTo'] ?? ( $currentTime * 1000 ) );

                $filterCreated = "";

                $createdFrom = intdiv( $createdFrom, 1000 );
                $createdTo = intdiv( $createdTo, 1000 );

                $filterCreated = !$showDeleted 
                    ? " AND created >= {$createdFrom} AND created <= {$createdTo}"
                    : " WHERE created >= {$createdFrom} AND created <= {$createdTo}";

                $q1 = $this->app->db->query( "SELECT * FROM users{$sqlWhereConditionHideDeleted}{$filterCreated} ORDER BY {$orderBy} LIMIT {$offset}, {$limit}" );

                $q2 = $this->app->db->query( "SELECT COUNT(*) AS table_rows FROM users{$sqlWhereConditionHideDeleted}{$filterCreated}" );

                if ( !$q2->num_rows ) {
                    $usersCount = 0;
                }
                else {
                    $usersCount = intval( $q2->fetch_assoc()['table_rows'] );
                    $q2->free();
                }
            }
            
            if ( !$q1->num_rows ) {
                $this->printError( 404, 131 );
            }

            $users = [];
            $dt = new \DateTime();

            while( $userData = $q1->fetch_assoc() ) {
                $userId = intval( $userData['user_id'] );
                $userRoleId = intval( $userData['role_id'] );

                $q2 = $this->app->db->query( "SELECT role FROM roles where role_id = {$userRoleId}" );

                if ( !$q2->num_rows ) {
                    $this->printError( 500, 1002 );
                }

                $userData['role_title'] = $q2->fetch_assoc()['role'];
                $q2->free();

                $userRatingId = intval( $userData['rating_id'] );

                $q3 = $this->app->db->query( "SELECT * FROM rating where rating_id = {$userRatingId}{$sqlWhereAndConditionHideDeleted}" );

                if ( !$q3->num_rows ) {
                    $this->printError( 500, 1003 );
                }

                $rating = $q3->fetch_assoc();
                $q3->free();

                $q4 = $this->app->db->query( "SELECT * FROM vehicles WHERE user_id = {$userId}{$sqlWhereAndConditionHideDeleted} ORDER BY created DESC" );

                $vehicles = [];

                while( $vehicle = $q4->fetch_assoc() ) {
                    $dt->setTimestamp( intval( $vehicle['created'] ) );
                    $vehicleCreated = $this->formatDateTimeRepresentation( $dt );

                    $dt->setTimestamp( intval( $vehicle['updated'] ) );
                    $vehicleUpdated = $this->formatDateTimeRepresentation( $dt );

                    if ( !array_key_exists( $vehicle['vehicle_uuid'], $vehicles ) ) {
                        $assets = [];

                        $q700 = $this->app->db->query( "SELECT * FROM assets WHERE related_to = \"vehicles\" AND relation_uuid = \"{$vehicle['vehicle_uuid']}\"" );

                        while( $asset = $q700->fetch_assoc() ) {
                            $dt->setTimestamp( intval( $asset['created'] ) );
                            $assetCreated = $this->formatDateTimeRepresentation( $dt );

                            if ( $myRole === 'admin' ) {
                                $assets[] = [
                                    'assetId' => $asset['asset_uuid'],
                                    'relatedTo' => $asset['related_to'],
                                    'description' => nl2br( $asset['description'] ),
                                    'fileType' => $asset['file_type'],
                                    'path' => $asset['path'],
                                    'created' => $assetCreated,
                                    'deleted' => boolval( $asset['deleted'] ),
                                ];
                            }
                            else {
                                $assets[] = [
                                    'assetId' => $asset['asset_uuid'],
                                    'relatedTo' => $asset['related_to'],
                                    'description' => nl2br( $asset['description'] ),
                                    'fileType' => $asset['file_type'],
                                    'path' => $asset['path'],
                                ];
                            }
                        }

                        $q700->free();

                        if ( $myRole === 'admin' ) {
                            $vehicles[ $vehicle['vehicle_uuid'] ] = [
                                'vehicleId' => $vehicle['vehicle_uuid'],
                                'details' => $vehicle['details'],
                                'assets' => $assets,
                                'regNumber' => $vehicle['reg_number'],
                                'vin' => $vehicle['vin'],
                                'engine' => $vehicle['engine'],
                                'overnightParkingVehicle' => $vehicle['overnight_parking_vehicle'],
                                'year' => intval( $vehicle['year'] ),
                                'retailValue' => intval( $vehicle['retail_value'] ),
                                'trackingDevice' => $vehicle['tracking_device'],
                                'useCase' => $vehicle['use_case'],
                                'businessDescription' => $vehicle['business_description'],
                                'accessories' => $vehicle['accessories'],
                                'created' => $vehicleCreated,
                                'updated' => $vehicleUpdated,
                                'deleted' => boolval( $vehicle['deleted'] ),
                            ];
                        }
                        else {
                            $vehicles[ $vehicle['vehicle_uuid'] ] = [
                                'vehicleId' => $vehicle['vehicle_uuid'],
                                'details' => $vehicle['details'],
                                'assets' => $assets,
                                'regNumber' => $vehicle['reg_number'],
                                'vin' => $vehicle['vin'],
                                'engine' => $vehicle['engine'],
                                'overnightParkingVehicle' => $vehicle['overnight_parking_vehicle'],
                                'year' => intval( $vehicle['year'] ),
                                'retailValue' => intval( $vehicle['retail_value'] ),
                                'trackingDevice' => $vehicle['tracking_device'],
                                'useCase' => $vehicle['use_case'],
                                'businessDescription' => $vehicle['business_description'],
                                'accessories' => $vehicle['accessories'],
                                'created' => $vehicleCreated,
                                'updated' => $vehicleUpdated,
                                'deleted' => boolval( $vehicle['deleted'] ),
                            ];
                        }
                    }
                }

                $q4->free();

                $vehicles = array_values( $vehicles );

                $dt->setTimestamp( intval( $userData['created'] ) );
                $userCreated = $this->formatDateTimeRepresentation( $dt );

                $dt->setTimestamp( intval( $userData['updated'] ) );
                $userUpdated = $this->formatDateTimeRepresentation( $dt );

                $dt->setTimestamp( intval( $userData['last_activity'] ) );
                $userLastActivity = $this->formatDateTimeRepresentation( $dt );

                $currentDate = new \DateTime( "now", new \DateTimeZone("UTC") );
                $birthDate = \DateTime::createFromFormat( 'U', $userData['birth_date'] );
                $birthDateFormatted = $this->formatDateTimeRepresentation( $birthDate );
                $userAge = intval( $currentDate->diff( $birthDate )->format( '%Y' ) );

                if ( $myRole === 'admin' ) {
                    $users[] = [
                        'accountId' => $userData['user_uuid'],
                        'username' => $userData['username'],
                        'role' => $userData['role_title'],
                        'firstName' => $userData['first_name'],
                        'lastName' => $userData['last_name'],
                        'avatar' => $userData['avatar'],
                        'driverLicensePhoto' => $userData['driver_license_photo'],
                        'birthDate' => intval( $userData['birth_date'] ) * 1000,
                        'birthDateFormatted' => $birthDateFormatted,
                        'age' => $userAge,
                        'address' => $userData['address'],
                        'email' => $userData['email'],
                        'cellphone' => $userData['cellphone'],
                        'phoneNumber' => $userData['phone'],
                        'clientIdNumber' => intval( $userData['client_id'] ),
                        'maritalStatus' => $userData['marital_status'],
                        'countryOfResidence' => $userData['country_of_residence'],
                        'yearOfIssueDriverLicense' => intval( $userData['year_of_issue_driver_license'] ),
                        'claimsHistory' => $userData['claims_history'],
                        'previousInsurer' => $userData['previous_insurer'],
                        'ratingId' => $rating['rating_uuid'],
                        'rating' => intval( $rating['rating'] ),
                        'vehicles' => $vehicles,
                        'created' => $userCreated,
                        'updated' => $userUpdated,
                        'lastActivity' => $userLastActivity,
                        'banned' => boolval( $userData['banned'] ),
                        'deleted' => boolval( $userData['deleted'] ),
                    ];
                }
                else if ( $myUserId === $userId ) {
                    $users[] = [
                        'accountId' => $userData['user_uuid'],
                        'username' => $userData['username'],
                        'role' => $userData['role_title'],
                        'firstName' => $userData['first_name'],
                        'lastName' => $userData['last_name'],
                        'avatar' => $userData['avatar'],
                        'driverLicensePhoto' => $userData['driver_license_photo'],
                        'birthDate' => intval( $userData['birth_date'] ) * 1000,
                        'age' => $userAge,
                        'address' => $userData['address'],
                        'email' => $userData['email'],
                        'cellphone' => $userData['cellphone'],
                        'phoneNumber' => $userData['phone'],
                        'clientIdNumber' => intval( $userData['client_id'] ),
                        'maritalStatus' => $userData['marital_status'],
                        'countryOfResidence' => $userData['country_of_residence'],
                        'yearOfIssueDriverLicense' => intval( $userData['year_of_issue_driver_license'] ),
                        'claimsHistory' => $userData['claims_history'],
                        'previousInsurer' => $userData['previous_insurer'],
                        'ratingId' => $rating['rating_uuid'],
                        'rating' => intval( $rating['rating'] ),
                        'vehicles' => $vehicles,
                        'created' => $userCreated,
                        'updated' => $userUpdated,
                        'lastActivity' => $userLastActivity,
                        'banned' => boolval( $userData['banned'] ),
                        'deleted' => boolval( $userData['deleted'] ),
                    ];
                }
            }

            $q1->free();

            if ( $myRole === 'anonymous' ) {
                $usersCount = 0;
            }

            $users = [
                "count" => $usersCount,
                "accounts" => $users
            ];

            $this->printResponse( $users );
        }
        else if ( $this->app->requestMethod === 'POST' ) {
            $dt = new \DateTime();

            $data = trim( @file_get_contents('php://input') );
            $data = @json_decode( $data );

            if ( !is_object( $data ) ) {
                $this->printError( 403, 1090 );
            }

            $userUuid = $this->app->db->escape( $data->accountId ?? "" );

            $ratingTableDataset = [];

            $ratingTableDataset['rating_uuid'] = Utils::generateUUID4();
            $ratingTableDataset['user_id'] = 0; // pre init
            $ratingTableDataset['rating'] = 1;
            $ratingTableDataset['created'] = $currentTime;

            $usersTableDataset = [];

            if ( !empty( $userUuid ) ) 
                $usersTableDataset['user_uuid'] = $userUuid;

            if ( !empty( $data->username ) ) 
                $usersTableDataset['username'] = $this->app->db->escape( $data->username );

            $password = $data->password ?? "";
            $newPassword = $data->newPassword ?? "";

            if ( !empty( $data->firstName ) ) 
                $usersTableDataset['first_name'] = $this->app->db->escape( $data->firstName );

            if ( !empty( $data->lastName ) ) 
                $usersTableDataset['last_name'] = $this->app->db->escape( $data->lastName );

            if ( !empty( $data->birthDate ) ) 
                $usersTableDataset['birth_date'] = intval( $data->birthDate / 1000 );

            if ( !empty( $data->address ) ) 
                $usersTableDataset['address'] = $this->app->db->escape( $data->address );

            if ( !empty( $data->email ) ) 
                $usersTableDataset['email'] = $this->app->db->escape( $data->email );

            if ( !empty( $data->cellphone ) ) 
                $usersTableDataset['cellphone'] = $this->app->db->escape( $data->cellphone );

            if ( !empty( $data->phoneNumber ) ) 
                $usersTableDataset['phone'] = $this->app->db->escape( $data->phoneNumber );

            if ( !empty( $data->clientIdNumber ) ) 
                $usersTableDataset['client_id'] = intval( $data->clientIdNumber );

            if ( !empty( $data->maritalStatus ) ) 
                $usersTableDataset['marital_status'] = $this->app->db->escape( $data->maritalStatus );

            if ( !empty( $data->countryOfResidence ) ) 
                $usersTableDataset['country_of_residence'] = $this->app->db->escape( $data->countryOfResidence );

            if ( !empty( $data->yearOfIssueDriverLicense ) ) 
                $usersTableDataset['year_of_issue_driver_license'] = intval( $data->yearOfIssueDriverLicense );

            if ( !empty( $data->claimsHistory ) ) 
                $usersTableDataset['claims_history'] = $this->app->db->escape( $data->claimsHistory );

            if ( !empty( $data->previousInsurer ) ) 
                $usersTableDataset['previous_insurer'] = $this->app->db->escape( $data->previousInsurer );
            
            $usersTableDataset['rating_id'] = 0; // !!! from table rating
            $usersTableDataset['role_id'] = 2; // 2 -> "user"
            $usersTableDataset['created'] = 0;
            $usersTableDataset['updated'] = 0;
            $usersTableDataset['last_activity'] = 0;
            $usersTableDataset['banned'] = 0;
            $usersTableDataset['deleted'] = 0;

            $mode = '';

            if ( !empty( $userUuid ) )
                $mode = 'update';
            else
                $mode = 'create';

            if ( $mode === 'create' ) {
                if ( $myUserId > 0 && $myRole !== 'admin' ) {
                    $this->printError( 403, 103 );
                }

                $usersTableDataset['user_uuid'] = Utils::generateUUID4();
                $usersTableDataset['client_id'] = intval( $data->clientIdNumber ?? random_int( 100000000000, 999999999999 ) );
                $usersTableDataset['created'] = $currentTime;

                if ( empty( $usersTableDataset['username'] ) || mb_strlen( $usersTableDataset['username'] ) < 5 ) {
                    $this->printError( 403, 1310 );
                }

                if ( !$password || mb_strlen( $password ) < 8 ) {
                    $this->printError( 403, 1311 );
                }

                $usersTableDataset['pswd_h'] = $this->app->db->escape( password_hash( $password, Settings::PASSWORD_HASH_ALGO ) );

                if ( empty( $usersTableDataset['email'] ) || !filter_var( $usersTableDataset['email'], FILTER_VALIDATE_EMAIL ) ) {
                    $this->printError( 403, 1312 );
                }

                $q7 = $this->app->db->query( "SELECT user_id FROM users WHERE username = \"{$usersTableDataset['username']}\"" );
            
                if ( $q7->num_rows ) {
                    $q7->free();
                    $this->printError( 403, 1313 );
                }

                $q8 = $this->app->db->query( "SELECT user_id FROM users WHERE email = \"{$usersTableDataset['email']}\"" );
            
                if ( $q8->num_rows ) {
                    $q8->free();
                    $this->printError( 403, 1314 );
                }

                $q9 = $this->app->db->query( "SELECT user_id FROM users WHERE client_id = {$usersTableDataset['client_id']}" );
            
                if ( $q9->num_rows ) {
                    $q9->free();
                    $this->printError( 403, 1315 );
                }

                $this->app->db->begin_transaction();

                $sqlSliceRating = [];

                foreach( $ratingTableDataset as $key => $value ) {
                    if ( is_int( $value ) || is_float( $value ) )
                        $sqlSliceRating[] = "{$key} = {$value}";
                    else
                        $sqlSliceRating[] = "{$key} = \"{$value}\"";
                }

                $sqlSliceRating = implode( ", ", $sqlSliceRating );

                $this->app->db->query( "INSERT INTO rating SET {$sqlSliceRating}" );
                $ratingId = intval( $this->app->db->insert_id );

                if ( !$ratingId ) {
                    $this->app->db->rollback();
                    $this->printError( 500, 1004 );
                }

                $usersTableDataset['rating_id'] = $ratingId;

                $sqlSliceUser = [];

                foreach( $usersTableDataset as $key => $value ) {
                    if ( is_int( $value ) || is_float( $value ) )
                        $sqlSliceUser[] = "{$key} = {$value}";
                    else
                        $sqlSliceUser[] = "{$key} = \"{$value}\"";
                }

                $sqlSliceUser = implode( ", ", $sqlSliceUser );

                $this->app->db->query( "INSERT INTO users SET {$sqlSliceUser}" );
                $userId = intval( $this->app->db->insert_id );

                if ( !$userId ) {
                    $this->app->db->rollback();
                    $this->printError( 500, 1005 );
                }

                $this->app->db->query( "UPDATE rating SET user_id = {$userId} WHERE rating_id = {$ratingId}" );

                if ( !$this->app->db->commit() ) {
                    $this->printError( 500, 1006 );
                }

                $q15 = $this->app->db->query( "SELECT * FROM users WHERE user_id = {$userId}" );
                
            }
            else if ( $mode === 'update' ) {
                if ( !$myUserId ) {
                    $this->printError( 403, 103 );
                }

                $usersTableDataset['updated'] = $currentTime;

                if ( $myRole !== 'admin' ) {
                    $userUuid = $this->app->user['user_uuid'];
    
                    /*
                    if ( !password_verify( $password, $this->app->user['pswd_h'] ) ) {
                        $this->printError( 403, 110 );
                    }
                    */

                    if ( !empty( $newPassword ) && mb_strlen( $newPassword ) < 8 ) {
                        $this->printError( 403, 1311 );
                    }

                    if ( !empty( $newPassword ) ) {
                        $usersTableDataset['pswd_h'] = $this->app->db->escape( password_hash( $newPassword, Settings::PASSWORD_HASH_ALGO ) );
                    }

                    unset( $usersTableDataset['user_id'], $usersTableDataset['user_uuid'], $usersTableDataset['username'], $usersTableDataset['email'], $usersTableDataset['client_id'], $usersTableDataset['rating_id'], $usersTableDataset['role_id'], $usersTableDataset['created'], $usersTableDataset['last_activity'], $usersTableDataset['banned'], $usersTableDataset['deleted'] );
                }
                else {
                    $q10 = $this->app->db->query( "SELECT user_id FROM users WHERE user_uuid = \"{$userUuid}\"" );
                
                    if ( !$q10->num_rows ) {
                        $q10->free();
                        $this->printError( 404, 1313 );
                    }

                    if ( !empty( $newPassword ) && mb_strlen( $newPassword ) < 8 ) {
                        $this->printError( 403, 1311 );
                    }

                    if ( !empty( $newPassword ) ) {
                        $usersTableDataset['pswd_h'] = $this->app->db->escape( password_hash( $newPassword, Settings::PASSWORD_HASH_ALGO ) );
                    }

                    unset( $usersTableDataset['user_id'], $usersTableDataset['user_uuid'], $usersTableDataset['rating_id'], $usersTableDataset['role_id'], $usersTableDataset['created'], $usersTableDataset['last_activity'] );

                    if ( isset( $data->banned ) )
                        $usersTableDataset['banned'] = intval( $data->banned ) > 0 ? 1 : 0;

                    if ( isset( $data->deleted ) )
                        $usersTableDataset['deleted'] = intval( $data->deleted ) > 0 ? 1 : 0;

                    if ( !empty( $usersTableDataset['username'] ) && mb_strlen( $usersTableDataset['username'] ) < 5 ) {
                        $this->printError( 403, 1310 );
                    }
    
                    if ( !empty( $usersTableDataset['email'] ) && !filter_var( $usersTableDataset['email'], FILTER_VALIDATE_EMAIL ) ) {
                        $this->printError( 403, 1312 );
                    }
    
                    if ( !empty( $usersTableDataset['username'] ) ) {
                        $q7 = $this->app->db->query( "SELECT user_id FROM users WHERE user_uuid != \"{$userUuid}\" AND username = \"{$usersTableDataset['username']}\"" );
                
                        if ( $q7->num_rows ) {
                            $q7->free();
                            $this->printError( 404, 1313 );
                        }
                    }

                    if ( !empty( $usersTableDataset['email'] ) ) {
                        $q8 = $this->app->db->query( "SELECT user_id FROM users WHERE user_uuid != \"{$userUuid}\" AND email = \"{$usersTableDataset['email']}\"" );
                
                        if ( $q8->num_rows ) {
                            $q8->free();
                            $this->printError( 404, 1314 );
                        }
                    }

                    if ( !empty( $usersTableDataset['client_id'] ) ) {
                        $q9 = $this->app->db->query( "SELECT user_id FROM users WHERE user_uuid != \"{$userUuid}\" AND client_id = {$usersTableDataset['client_id']}" );
            
                        if ( $q9->num_rows ) {
                            $q9->free();
                            $this->printError( 404, 1315 );
                        }
                    }
                }

                // ставим через assets
                /*
                if ( !empty( $data->avatar ) ) {
                    if ( Utils::startsWith( $data->avatar, "/assets/{$userUuid}/" ) ) {
                        $usersTableDataset['avatar'] = $this->app->db->escape( $data->avatar );
                    }
                }
    
                if ( !empty( $data->driverLicensePhoto ) ) {
                    if ( Utils::startsWith( $data->driverLicensePhoto, "/assets/{$userUuid}/" ) ) {
                        $usersTableDataset['driver_license_photo'] = $this->app->db->escape( $data->driverLicensePhoto );
                    }
                }
                */

                $sqlSliceUser = [];

                foreach( $usersTableDataset as $key => $value ) {
                    if ( is_int( $value ) || is_float( $value ) )
                        $sqlSliceUser[] = "{$key} = {$value}";
                    else
                        $sqlSliceUser[] = "{$key} = \"{$value}\"";
                }

                $sqlSliceUser = implode( ", ", $sqlSliceUser );

                $this->app->db->query( "UPDATE users SET {$sqlSliceUser} WHERE user_uuid = \"{$userUuid}\"" );

                $q70 = $this->app->db->query( "SELECT username FROM users WHERE user_uuid = \"{$userUuid}\"" );
                $username = $q70->fetch_assoc()['username'];
                $q70->free();

                $actionsTableDataset = [
                    'user_uuid' => $this->app->user['user_uuid'],
                    'username' => $this->app->user['username'],
                    'role' => $this->app->user['role_title'],
                    'to_user_uuid' => $userUuid,
                    'to_username' => $username,
                    'entity_id' => '',
                    'action' => 'update',
                    'fields' => $this->app->db->escape( $sqlSliceUser ),
                    'where_clause' => $this->app->db->escape( "user_uuid = \"{$userUuid}\"" ),
                    'description' => 'updated account',
                    'created' => $currentTime,
                    'deleted' => 0 
                ];
    
                $this->setLog( $actionsTableDataset );

                $q15 = $this->app->db->query( "SELECT * FROM users WHERE user_uuid = \"{$userUuid}\"" );
            }

            if ( !$q15->num_rows ) {
                $this->printError( 500, 1005 );
            }

            $usersTableDataset = $q15->fetch_assoc();
            $q15->free();

            $apiResponse = [
                'accountId' => $usersTableDataset['user_uuid'],
                'email' => $usersTableDataset['email'],
                'username' => $usersTableDataset['username'],
                'role' => 'user',
                'firstName' => $usersTableDataset['first_name'],
                'lastName' => $usersTableDataset['last_name'],
            ];

            if ( $mode === 'create' ) {
                [ $accessToken, $accessTokenCreatedTimestamp, $accessTokenExpiresTimestamp, $accessTokenExpires ] = $this->getAccessToken();

                $accessTokenHashed = hash_hmac( "sha256", $accessToken, Settings::ACCESS_TOKEN_HASH_SECRET );

                $this->app->db->query( "DELETE FROM sessions WHERE expires < {$currentTime}" );

                $this->app->db->query( "INSERT INTO sessions SET 
                    user_id = {$userId}, 
                    ip = \"{$this->app->ip_addr}\", 
                    access_token = \"{$accessTokenHashed}\",
                    created = {$accessTokenCreatedTimestamp},
                    expires = {$accessTokenExpiresTimestamp}
                " );

                $country = $this->app->db->escape( $this->app->geo_country );
                $userAgent = $this->app->db->escape( $this->app->user_agent );

                $this->app->db->query( "INSERT INTO authentications SET 
                    user_id = {$userId}, 
                    ip = \"{$this->app->ip_addr}\", 
                    country = \"{$country}\", 
                    user_agent = \"{$userAgent}\",
                    created = {$accessTokenCreatedTimestamp}
                " );

                $apiResponse['token'] = $accessToken;
                $apiResponse['tokenExpirationTime'] = $accessTokenExpires;
            }

            $this->printResponse( $apiResponse );
        }
        else {
            $this->printError( 405, 106 );
        }
    }

    private function setLog( array $actionsTableDataset ) : void {
        $sqlSliceActions = [];

        if ( empty( $actionsTableDataset ) ) {
            $this->printError( 500, 1020 );
        }

        foreach( $actionsTableDataset as $key => $value ) {
            if ( is_int( $value ) || is_float( $value ) )
                $sqlSliceActions[] = "{$key} = {$value}";
            else
                $sqlSliceActions[] = "{$key} = \"{$value}\"";
        }

        $sqlSliceActions = implode( ", ", $sqlSliceActions );

        $this->app->db->query( "INSERT INTO actions SET {$sqlSliceActions}" );
    }

    private function formatDateTimeRepresentation( \DateTimeInterface $dt ) : string {
        //return $dt->format( 'Y-m-d\TH:i:s.' ) . substr( $dt->format('u'), 0, 3 ) . 'Z';
        //return $dt->format( 'Y-m-d\TH:i:s.vp' );
        return $dt->format( 'Y-m-d\TH:i:s.v' ) . 'Z';
    }

    private function deleteUploadedFiles( string|array $files ) : void {
        if ( isset( $files ) ) {
            if ( !is_array( $files ) ) {
                if ( file_exists( $files ) ) @unlink( $files );
            }
            else {
                foreach( $files as $file ) {
                    if ( file_exists( $file ) ) @unlink( $file );
                }
            }
        }
    }

    private function printError( int $httpCode = 404, int $code = 0 ) : void {
        $this->printHeaders( $httpCode );

        if ( $httpCode === 401 ) {
            header( 'WWW-Authenticate: Bearer realm="DefaultRealm"' );
        }

        $text = $this->app->lang[ 'api_code_' . $code ] ?? throw new \Exception( $this->app->lang[ 'api_code_1000' ] );

        echo json_encode( [
            "state" => "fail",
            "code" => $code,
            "message" => $text
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE );
        exit();
    }

    private function printResponse( array $data = [] ) : void {
        $this->printHeaders( 200 );

        $myRole = $this->app->user['role_title'];

        if ( $myRole === 'admin' ) {
            $executionTime = round( microtime(true) - $_SERVER['REQUEST_TIME_FLOAT'], 3 );
            $data = [ "executionTime" => $executionTime ] + $data;
        }

        $data = [ "state" => "ok" ] + $data;

        echo json_encode( $data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE );
        exit();
    }

    private function printHeaders( int $httpCode = 200 ) : void {
        // preflight request
        if ( $this->app->requestMethod === 'OPTIONS' ) {
            header( "{$this->app->http_protocol} 204" );
            header( "Access-Control-Allow-Origin: {$this->app->http_origin}" );
            header( "Vary: Origin" );
            header( "Access-Control-Allow-Credentials: true" );
            header( "Access-Control-Allow-Headers: Content-Type, Authorization, Cookie" );
            header( "Access-Control-Allow-Methods: POST, GET, OPTIONS" );
            header( "Access-Control-Max-Age: 86400" );
            exit();
        }
        // GET, POST
        else if ( in_array( $this->app->requestMethod, [ 'GET', 'POST' ] ) ) {
            header( "{$this->app->http_protocol} {$httpCode}" );
            header( "Access-Control-Allow-Origin: {$this->app->http_origin}" );
            header( "Vary: Origin" );
            header( "Access-Control-Allow-Credentials: true" );
            header( "Access-Control-Expose-Headers: X-Extra-Data" );
            header( "Access-Control-Max-Age: 86400" );
            header( "Content-Type: application/json; charset=UTF-8" );
        }
        else {
            header( "{$this->app->http_protocol} 501" );
            die("Not implemented.");
        }
    }
}