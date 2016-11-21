<?php
/**
 * This file is part of DoctrineRestDriver.
 *
 * DoctrineRestDriver is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * DoctrineRestDriver is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with DoctrineRestDriver.  If not, see <http://www.gnu.org/licenses/>.
 */

namespace Circle\DoctrineRestDriver\Security;

use Circle\DoctrineRestDriver\Types\Request;

/**
 * This file can be used in the driver's config to use
 * the target API with basic http authentication
 *
 * @author    Liviu Oprisan
 */
class JwtAuthentication implements AuthStrategy {

    /**
     * @var array
     */
    private $config;

    /**
     * HttpBasicAuthentication constructor
     *
     * @param array $config
     */
    public function __construct(array $config) {
        $this->config = $config;
    }

    /**
     * {@inheritdoc}
     */
    public function transformRequest(Request $request) {
        
        $jwtToken = $this->getJwtToken();
        
        $options  = $request->getCurlOptions();
        
        $concatenateBeforeToken = "";
        if(isset($this->config['driverOptions']['jwt_prefix']))
        {
            $concatenateBeforeToken = $this->config['driverOptions']['jwt_prefix'];
        }
        
        $headers  = empty($options[CURLOPT_HTTPHEADER]) ? [] : $options[CURLOPT_HTTPHEADER];
        array_push($headers, 'X-API-Token: ' . $concatenateBeforeToken . $jwtToken);
        $options[CURLOPT_HTTPHEADER] = $headers;

        return $request->setCurlOptions($options);
    }
    
    /**
     * token is cached in session; it is revalidated "revalidate_token_time" seconds before expire 
     * (defaults to 5 seconds)
     * @return string
     */
    private function getJwtToken()
    {
        if(!isset($_SESSION["doctrine_rest_driver_jwt_token"]))
        {
            $_SESSION["doctrine_rest_driver_jwt_token"] = $this->getJwtTokenFromRemote();
        }
        else if($this->shouldRefreshToken($_SESSION["doctrine_rest_driver_jwt_token"]))
        {
            $_SESSION["doctrine_rest_driver_jwt_token"] = $this->getJwtTokenFromRemote();
        }
        
        return $_SESSION["doctrine_rest_driver_jwt_token"];
    }
    
    /**
     * checks if token is about to expire - 5 seconds before expire date 
     * or "revalidate_token_time" before expire from config -> dbal ->
     * -> connections -> options -> revalidate_token_time, if set
     * @param string $token
     * @return boolean
     */
    private function shouldRefreshToken($token)
    {
        
        $elements = explode('.', $token);
        $payload = json_decode(base64_decode($elements[1]));
        
        $expireTimestamp = $payload->iat;
        $revalidateTime = 5;
        if(isset($this->config['driverOptions']['revalidate_token_time']))
        {
            $revalidateTime = $this->config['driverOptions']['revalidate_token_time'];
        }
        
        $date = new \DateTime();
        $timestamp = $date->getTimestamp();
        
        
        $expiresAt = $expireTimestamp + $revalidateTime;
        
        if( $expiresAt < $timestamp)
        {
            return true;
        }
        
        return false;
    }
    
    /**
     * 
     * @return string
     */
    private function getJwtTokenFromRemote()
    {
        
        $request_data = array(
                              'username' => $this->config['user']
                            , 'password' => $this->config['password']);
        $jwtUrl = $this->config['driverOptions']['jwt_url'];
        $token_response = $this->getPostResponseAsArray($jwtUrl, $request_data);
        
        $token = $token_response["token"];
        
        return $token;
    }
    
    /**
     * uses file_get_contents; maybe use curl instead?
     * 
     * @param string $url
     * @param array $request_data
     * @return array
     * @throws \Exception
     */
    private function getPostResponseAsArray($url, array $request_data)
    {
        // use key 'http' even if you send the request to https://...
        $options = array(
            'http' => array(
                'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
                'method'  => "POST",
                'content' => http_build_query($request_data)
            )
        );
        $context  = stream_context_create($options);
        $result = file_get_contents($url, false, $context);
        if ($result === FALSE) 
        { 
            throw new \Exception("request to api failed."); 
        }
        return json_decode($result, true);
    }


}