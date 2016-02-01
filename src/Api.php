<?php

namespace WardenApi;

use GuzzleHttp\Client;
use Psr\Http\Message\ResponseInterface;
use WardenApi\Exception\EncryptionException;
use WardenApi\Exception\WardenBadResponseException;

/**
 * The API for communicating with the Warden server application.
 *
 * @author John Ennew <johne@deeson.co.uk>
 * @author Mike Davis <miked@deeson.co.uk>
 */
class Api {

  /**
   * @var string
   */
  protected $wardenUrl;

  /**
   * @var string
   */
  protected $wardenPublicKey = '';

  /**
   * @var string
   */
  protected $username = '';

  /**
   * @var string
   */
  protected $password = '';

  /**
   * @var string
   */
  protected $certificatePath;

  /**
   * @param string $warden_url
   *   The URL to the server.
   * @param string $username
   *   (optional) The basic HTTP username of warden if set.
   * @param string $password
   *   (optional) The basic HTTP password of warden if set.
   * @param string $certificatePath
   *   (optional) Set to a string to specify the path to a file containing a
   *   PEM formatted client side certificate.
   */
  public function __construct($warden_url, $username = '', $password = '', $certificatePath = '') {
    $this->wardenUrl = $warden_url;
    $this->username = $username;
    $this->password = $password;
    $this->certificatePath = $certificatePath;
  }

  /**
   * @return string
   */
  public function getWardenUrl() {
    return $this->wardenUrl;
  }

  /**
   * @return string
   */
  public function getUsername() {
    return $this->username;
  }

  /**
   * @return string
   */
  public function getPassword() {
    return $this->password;
  }

  /**
   * @return string
   */
  public function getCertificatePath() {
    return $this->certificatePath;
  }

  /**
   * Get the public key.
   *
   * @throws WardenBadResponseException
   *   If the response status was not 200
   */
  public function getPublicKey() {

    if (empty($this->wardenPublicKey)) {
      $result = $this->request('/public-key');
      $this->wardenPublicKey = base64_decode($result->getBody());
    }

    return $this->wardenPublicKey;
  }

  /**
   * Check the validity of a token sent from Warden.
   *
   * To prove a request came from the Warden application, Warden encrypts
   * the current timestamp using its private key which can be decrypted with
   * its public key. Only the true Warden can produce the encrypted message.
   * Since it is possible to reply the token, the token only lasts for
   * 20 seconds.
   *
   * @param string $encryptedRemoteToken
   *   The token sent from the warden site which has been encrypted
   *   with Warden's private key.
   *
   * @return bool
   *   TRUE if we can trust the token.
   */
  public function isValidWardenToken($encryptedRemoteToken, $timestamp) {
    $envelope = json_decode(base64_decode($encryptedRemoteToken));

    if (!is_object($envelope) || empty($envelope->time) || empty($envelope->signature)) {
      return FALSE;
    }

    $remoteTimestamp = base64_decode($envelope->time);

    if (!is_numeric($remoteTimestamp)
      || ($remoteTimestamp > $timestamp + 20)
      || ($remoteTimestamp < $timestamp - 20)
    ) {
      return FALSE;
    }

    $result = openssl_verify($remoteTimestamp, base64_decode($envelope->signature), $this->getPublicKey());
    return $result === 1;
  }

  /**
   * Encrypt a plaintext message.
   *
   * @param mixed $data
   *   The data to encrypt for transport.
   *
   * @return string
   *   The encoded message
   *
   * @throws EncryptionException
   *   If there is a problem with the encryption process.
   * @throws WardenBadResponseException
   *   If the response status from Warden was not 200 when retrieving the
   *   public key.
   */
  public function encrypt($data) {
    $plaintext = json_encode($data);

    $public_key = $this->getPublicKey();

    $result = openssl_seal($plaintext, $message, $keys, array($public_key));

    if ($result === FALSE || empty($keys[0]) || empty($message) || $message === $plaintext) {
      throw new EncryptionException('Unable to encrypt a message: ' . openssl_error_string());
    }

    $envelope = (object) array(
      'key' => base64_encode($keys[0]),
      'message' => base64_encode($message),
    );

    return base64_encode(json_encode($envelope));
  }

  /**
   * Decrypt a message which was encrypted with the Warden private key.
   *
   * @param string $cypherText
   *   The encrypted text
   * @return mixed
   *   The original data
   *
   * @throws EncryptionException
   *   If there was a problem with the decryption process.
   * @throws WardenBadResponseException
   *   If the response status from Warden was not 200 when retrieving the
   *   public key.
   */
  public function decrypt($cypherText) {
    $envelope = json_decode(base64_decode($cypherText));

    if (!is_object($envelope) || empty($envelope->key) || empty($envelope->message)) {
      throw new EncryptionException('Encrypted message is not understood');
    }

    $key = base64_decode($envelope->key);
    $message = base64_decode($envelope->message);

    $decrypted = '';
    $result = openssl_open($message, $decrypted, $key, $this->getPublicKey());

    if ($result === FALSE) {
      throw new EncryptionException('Unable to decrypt a message: ' . openssl_error_string());
    }

    return json_decode($decrypted);
  }

  /**
   * Send the site data to Warden.
   *
   * @param array $data
   *
   * @throws WardenBadResponseException
   *   If the response status was not 200
   */
  public function postSiteData(array $data) {
    $encrypted_message = $this->encrypt($data);
    $this->request('/site-update', $encrypted_message);
  }

  /**
   * Send a message to warden
   *
   * @param string $path
   *   The query path including the leading slash (e.g. '/public-key')
   * @param string $content
   *   The body of the request. If this is not empty, the request is a post.
   *
   * @return ResponseInterface
   *   The response object
   *
   * @throws WardenBadResponseException
   *   If the response status was not 200
   */
  public function request($path, $content = '') {
    $url = $this->wardenUrl . $path;

    $options = [];

    if (!empty($this->username)) {
      $options['auth'] = [ $this->username, $this->password];
    }

    $method = 'GET';
    if (!empty($content)) {
      $method = 'POST';
      $options['body'] = $content;
    }

    if (!empty($this->certificatePath)) {
      $options['cert'] = $this->certificatePath;
    }

    $client = new Client();

    $res = $client->request($method, $url, $options);

    if ($res->getStatusCode() !== 200) {
      throw new WardenBadResponseException('Unable to communicate with Warden (' . $res->getStatusCode() . ') ' . $res->getReasonPhrase());
    }

    return $res;
  }

}
