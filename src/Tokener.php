<?php

/*
 * @author Vítor Roque <roque@konariumteam.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 *
 * PHP version 7.2
 */
namespace Konarium\Token;

class Tokener {

	public $header;

	/**
	 * Constructor
	 *
	 * Create the base header
	 * 
	 */
	public function __construct() {
			
		$header = [
			'alg' => 'HS256',
			'typ' => 'JWT'
		];

		$this->header = base64_encode(json_encode($header));

	}

	/**
	 * Create a JWT token based on 
	 * the options specified on the payload
	 * 
	 * @param  array  $payload   options and data which will stay on the token
	 * @param  string $secretKey Secret Key to secure your token
	 * @return string $signature Returns a string that contains the hash of your token
	 */
	public function create($payload = [], $secretKey) {

		$payload = base64_encode(json_encode($payload));
		$signature = hash_hmac('sha256', "$this->header.$payload", $secretKey, true);
		$signature = base64_encode($signature);
		$hash = "{$this->header}.{$payload}.{$signature}";
		return $hash;

	}


	/**
	 * Verify the token if is valid or not
	 * @param  string $token     The string hash which was created before
	 * @param  string $secretKey [description]
	 * @return string            Error handler
	 */
	public function verify($token = '', $secretKey = '') {

		$token = explode('.', $token);

		[$header, $payload, $signature] = $token;

		$valid = hash_hmac('sha256', "$header.$payload", $secretKey, true);
		$valid = base64_encode($valid);

		if($signature == $valid) {
			$payload = json_decode(base64_decode($payload));
			if(isset($payload->nbf)) {
				
				if(date('Y-m-d') < $payload->nbf) {

					return 'Token not valid before';
				
				} else {

					return 'Token valid';

				}
				
			}else if($payload->exp) {

				if(date('Y-m-d') > $payload->exp) {

					return 'Token expired';

				} else {

					return 'Token valid';

				}
			
			} else {

				return 'Token valid';

			}
			

		} else {

			return 'Token invalid';

		}


	}


}