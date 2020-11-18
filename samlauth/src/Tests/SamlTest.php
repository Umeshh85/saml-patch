<?php

namespace Drupal\samlauth\Tests;

use Drupal\Tests\BrowserTestBase;
use Drupal\Component\Serialization\Yaml;

/**
 * Tests SAML authentication.
 *
 * @group samlauth
 */
class SamlTest extends BrowserTestBase {

  /**
   * We don't need a strict schema. There *isn't* one.
   */
  protected $strictConfigSchema = FALSE;

  /**
   * Modules to Enable.
   */
  public static $modules = ['samlauth'];

  /**
   * Return info on the test.
   */
  public static function getInfo() {
    return [
      'name' => 'Tests SAML authentication',
      'description' => 'Functional tests for the samlauth module functionality.',
      'group' => 'samlauth',
    ];
  }

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * {@inheritdoc}
   */
  public function setUp() {
    parent::setUp();

    // Import testshib config.
    $config = drupal_get_path('module', 'samlauth') . '/test_resources/samlauth.authentication.yml';;
    $config = file_get_contents($config);
    $config = Yaml::decode($config);
    \Drupal::configFactory()->getEditable('samlauth.authentication')->setData($config)->save();
  }

  /**
   * Tests the Admin Page.
   */
  public function testAdminPage() {
    // Test that the administration page is present.
    // These aren't very good tests, but the form and config systems are already
    // thoroughly tested, so we're just checking the basics here.
    $web_user = $this->drupalCreateUser(['configure saml']);
    $this->drupalLogin($web_user);
    $this->drupalGet('admin/config/people/saml');
    $this->assertText('Login / Logout', 'Login / Logout fieldset present');
    $this->assertText('Service Provider', 'SP fieldset present');
    $this->assertText('Identity Provider', 'iDP fieldset present');
    $this->assertText('User Info and Syncing', 'User Info and Syncing fieldset present');
    $this->assertText('SAML Message Construction', 'SAML Message Construction fieldset present');
    $this->assertText('SAML Message Validation', 'SAML Message Validation fieldset present');
  }

  /**
   * Tests metadata coming back.
   */
  public function testMetadata() {
    $web_user = $this->drupalCreateUser(['view sp metadata']);
    $this->drupalLogin($web_user);

    // Test that we get metadata.
    $this->drupalGet('saml/metadata');
    $this->assertResponse(200, 'SP metadata is accessible');
    $this->assertRaw('entityID="samlauth"', 'Entity ID found in the metadata');
  }

}
