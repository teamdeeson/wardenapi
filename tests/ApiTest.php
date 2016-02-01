<?php

namespace WardenApi;

class ApiTest extends \PHPUnit_Framework_TestCase {

  /**
   * @Test
   * Test the basic operation to create a Warden API connection.
   */
  public function testCreate() {
    $api = new Api('http://www.example.com', 'user', 'pass', '/dev/null');

    $this->assertEquals('http://www.example.com', $api->getWardenUrl());
    $this->assertEquals('user', $api->getUsername());
    $this->assertEquals('pass', $api->getPassword());
    $this->assertEquals('/dev/null', $api->getCertificatePath());
  }

}