<?php

namespace Drupal\samlauth;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Url;
use Drupal\externalauth\ExternalAuth;
use Drupal\samlauth\Event\SamlauthEvents;
use Drupal\samlauth\Event\SamlauthUserLinkEvent;
use Drupal\samlauth\Event\SamlauthUserSyncEvent;
use Drupal\Core\TempStore\PrivateTempStoreFactory;
use Drupal\user\UserInterface;
use Exception;
use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Error;
use Psr\Log\LoggerInterface;
use RuntimeException;
use GuzzleHttp\ClientInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

/**
 * Governs communication between the SAML toolkit and the IdP / login behavior.
 */
class SamlService {
    /**
   * The http client service.
   *
   * @var \GuzzleHttp\ClientInterface
   */
  protected $httpClient;


  /**
   * An Auth object representing the current request state.
   *
   * @var \OneLogin\Saml2\Auth
   */
  protected $samlAuth;

  /**
   * The ExternalAuth service.
   *
   * @var \Drupal\externalauth\ExternalAuth
   */
  protected $externalAuth;

  /**
   * A configuration object containing samlauth settings.
   *
   * @var \Drupal\Core\Config\ImmutableConfig
   */
  protected $config;

  /**
   * The EntityTypeManager service.
   *
   * @var \Drupal\Core\Entity\EntityTypeManagerInterface
   */
  protected $entityTypeManager;

  /**
   * A logger instance.
   *
   * @var \Psr\Log\LoggerInterface
   */
  protected $logger;

  /**
   * The event dispatcher.
   *
   * @var \Symfony\Component\EventDispatcher\EventDispatcherInterface
   */
  protected $eventDispatcher;

  /**
   * The tempstore factory.
   *
   * @var \Drupal\Core\TempStore\PrivateTempStoreFactory
   */
  protected $tempStoreFactory;

  /**
   * Constructor for Drupal\samlauth\SamlService.
   *
   * @param \Drupal\externalauth\ExternalAuth $external_auth
   *   The ExternalAuth service.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   The EntityTypeManager service.
   * @param \Psr\Log\LoggerInterface $logger
   *   A logger instance.
   * @param \Symfony\Component\EventDispatcher\EventDispatcherInterface $event_dispatcher
   *   The event dispatcher.
   * @param \Drupal\Core\TempStore\PrivateTempStoreFactory $temp_store_factory
   *   A temp data store factory object.
   */
  public function __construct(ClientInterface $http_client,ExternalAuth $external_auth, ConfigFactoryInterface $config_factory, EntityTypeManagerInterface $entity_type_manager, LoggerInterface $logger, EventDispatcherInterface $event_dispatcher, PrivateTempStoreFactory $temp_store_factory) {
    $this->httpClient = $http_client;
    $this->externalAuth = $external_auth;
    $this->config = $config_factory->get('samlauth.authentication');
    $this->entityTypeManager = $entity_type_manager;
    $this->logger = $logger;
    $this->eventDispatcher = $event_dispatcher;
    $this->tempStoreFactory = $temp_store_factory->get('samlauth');
  }

  /**
   * Show metadata about the local sp. Use this to configure your saml2 IdP.
   *
   * @return mixed xml string representing metadata
   *
   * @throws \OneLogin\Saml2\Error
   */
  public function getMetadata() {
    $settings = $this->getSamlAuth()->getSettings();
    $metadata = $settings->getSPMetadata();
    $errors = $settings->validateMetadata($metadata);

    if (empty($errors)) {
      return $metadata;
    }
    else {
      throw new Error('Invalid SP metadata: ' . implode(', ', $errors), Error::METADATA_SP_INVALID);
    }
  }

  /**
   * Initiates a SAML2 authentication flow and redirects to the IdP.
   *
   * @param string $return_to
   *   (optional) The path to return the user to after successful processing by
   *   the IdP.
   * @param array $parameters
   *   (optional) Extra query parameters to add to the returned redirect URL.
   *
   * @return string
   *   The URL of the single sign-on service to redirect to, including query
   *   parameters.
   */
  public function login($return_to = NULL, $parameters = []) {
    $url = $this->getSamlAuth()->login($return_to, $parameters, FALSE, FALSE, TRUE, $this->config->get('request_set_name_id_policy') ?? TRUE);
    if ($this->config->get('debug_log_saml_out')) {
      $this->logger->debug('Sending SAML login request: <pre>@message</pre>', ['@message' => $this->getSamlAuth()->getLastRequestXML()]);
    }
    return $url;
  }

  /**
   * Initiates a SAML2 logout flow and redirects to the IdP.
   *
   * @param null $return_to
   *   (optional) The path to return the user to after successful processing by
   *   the IdP.
   * @param array $parameters
   *   (optional) Extra query parameters to add to the returned redirect URL.
   *
   * @return string
   *   The URL of the single logout service to redirect to, including query
   *   parameters.
   */
  public function logout($return_to = NULL, $parameters = []) {
    $url = $this->getSamlAuth()->logout(
      $return_to,
      $parameters,
      $this->tempStoreFactory->get('name_id'),
      $this->tempStoreFactory->get('session_index'),
      TRUE,
      $this->tempStoreFactory->get('name_id_format')
    );
    if ($this->config->get('debug_log_saml_out')) {
      $this->logger->debug('Sending SAML logout request: <pre>@message</pre>', ['@message' => $this->getSamlAuth()->getLastRequestXML()]);
    }
    return $url;
  }

  /**
   * Processes a SAML response (Assertion Consumer Service).
   *
   * First checks whether the SAML request is OK, then takes action on the
   * Drupal user (logs in / maps existing / create new) depending on attributes
   * sent in the request and our module configuration.
   *
   * @throws \Exception
   */
  public function acs() {
    if ($this->config->get('debug_log_in')) {
      if (isset($_POST['SAMLResponse'])) {
        $response = base64_decode($_POST['SAMLResponse']);
        if ($response) {
          $this->logger->debug("ACS received 'SAMLResponse' in POST request (base64 decoded): <pre>@message</pre>", ['@message' => $response]);
        }
        else {
          $this->logger->warning("ACS received 'SAMLResponse' in POST request which could not be base64 decoded: <pre>@message</pre>", ['@message' => $_POST['SAMLResponse']]);
        }
      }
      else {
        // Not sure if we should be more detailed...
        $this->logger->warning("HTTP request to ACS is not a POST request, or contains no 'SAMLResponse' parameter.");
      }
    }
    $baseencode = base64_encode($response);
   // Make API call.
     $url = 'https://www.dev.mvp-reef.va.gov/v3/saml_sso/drupal/assertion_consumer_service_with_token';
     $body = array('SAMLResponse'=> $baseencode,'RelayState' => '');
    try {
       $result = $this->httpClient->post( $url,
         [
         'body' => json_encode($body),
          'headers' => [
          'Content-Type' => 'application/json',
         ],
        ]
       );
        if ($result->getStatusCode() == 200) {
        $response = json_decode($result->getBody()->getContents());
        $session = \Drupal::request()->getSession();
        $session->set('samlauth_token', $response->data->token);
        $session->set('samlauth_email', base64_decode($response->data->email));
        }
     }  
     catch (ClientException $e) {
      \Drupal::logger('samlauth')->error("Error ".$e->getMessage());
     }
    // This call can either set an error condition or throw a
    // \OneLogin_Saml2_Error exception, depending on whether or not we are
    // processing a POST request. Don't catch the exception.
    $this->getSamlAuth()->processResponse();

    if ($this->config->get('debug_log_saml_in')) {
      $this->logger->debug('ACS received SAML response: <pre>@message</pre>', ['@message' => $this->getSamlAuth()->getLastResponseXML()]);
    }
    
    // Now look if there were any errors and also throw.
    $errors = $this->getSamlAuth()->getErrors();
    if (!empty($errors)) {
      // We have one or multiple error types / short descriptions, and one
      // 'reason' for the last error.
      throw new RuntimeException('Error(s) encountered during processing of ACS response. Type(s): ' . implode(', ', array_unique($errors)) . '; reason given for last error: ' . $this->getSamlAuth()->getLastErrorReason());
    }

    if (!$this->isAuthenticated()) {
      throw new RuntimeException('Could not authenticate.');
    }

    $unique_id = $this->getAttributeByConfig('unique_id_attribute');
    if (!$unique_id) {
      throw new Exception('Configured unique ID is not present in SAML response.');
    }

    $account = $this->externalAuth->load($unique_id, 'samlauth');
    if (!$account) {
      $this->logger->debug('No matching local users found for unique SAML ID @saml_id.', ['@saml_id' => $unique_id]);

      // Try to link an existing user: first through a custom event handler,
      // then by name, then by e-mail.
      if ($this->config->get('map_users')) {
        $event = new SamlauthUserLinkEvent($this->getAttributes());
        $this->eventDispatcher->dispatch(SamlauthEvents::USER_LINK, $event);
        $account = $event->getLinkedAccount();
        if (!$account) {
          // The linking by name / e-mail cannot be bypassed at this point
          // because it makes no sense to create a new account from the SAML
          // attributes if one of these two basic properties is already in use.
          // (In this case a newly created and logged-in account would get a
          // cryptic machine name because  synchronizeUserAttributes() cannot
          // assign the proper name while saving.)
          $name = $this->getAttributeByConfig('user_name_attribute');
          if ($name && $account_search = $this->entityTypeManager->getStorage('user')->loadByProperties(['name' => $name])) {
            $account = reset($account_search);
            $this->logger->info('Matching local user @uid found for name @name (as provided in a SAML attribute); associating user and logging in.', ['@name' => $name, '@uid' => $account->id()]);
          }
          else {
            $mail = $this->getAttributeByConfig('user_mail_attribute');
            if ($mail && $account_search = $this->entityTypeManager->getStorage('user')->loadByProperties(['mail' => $mail])) {
              $account = reset($account_search);
              $this->logger->info('Matching local user @uid found for e-mail @mail (as provided in a SAML attribute); associating user and logging in.', ['@mail' => $mail, '@uid' => $account->id()]);
            }
          }
        }
      }

      if ($account) {
        // There is a chance that the following call will not actually link the
        // account (if a mapping to this account already exists from another
        // unique ID). If that happens, it does not matter much to us; we will
        // just log the account in anyway. Next time the same not-yet-linked
        // user logs in, we will again try to link the account in the same way
        // and (falsely) log that we are associating the user.
        $this->externalAuth->linkExistingAccount($unique_id, 'samlauth', $account);
      }
    }

    // If we haven't found an account to link, create one from the SAML
    // attributes.
    if (!$account) {
      if ($this->config->get('create_users')) {
        // The register() call will save the account. We want to:
        // - add values from the SAML response into the user account;
        // - not save the account twice (because if the second save fails we do
        //   not want to end up with a user account in an undetermined state);
        // - reuse code (i.e. call synchronizeUserAttributes() with its current
        //   signature, which is also done when an existing user logs in).
        // Because of the third point, we are not passing the necessary SAML
        // attributes into register()'s $account_data parameter, but we want to
        // hook into the save operation of the user account object that is
        // created by register(). It seems we can only do this by implementing
        // hook_user_presave() - which calls our synchronizeUserAttributes().
        $account = $this->externalAuth->register($unique_id, 'samlauth');

        $this->externalAuth->userLoginFinalize($account, $unique_id, 'samlauth');
      }
      else {
        throw new UserVisibleException('No existing user account matches the SAML ID provided. This authentication service is not configured to create new accounts.');
      }
    }
    elseif ($account->isBlocked()) {
      throw new UserVisibleException('Requested account is blocked.');
    }
    else {
      // Synchronize the user account with SAML attributes if needed.
      $this->synchronizeUserAttributes($account);

      $this->externalAuth->userLoginFinalize($account, $unique_id, 'samlauth');
    }

    // Set some request properties in local private storage. We can use these on
    // logout.
    foreach ([
      'session_index' => $this->samlAuth->getSessionIndex(),
      'session_expiration' => $this->samlAuth->getSessionExpiration(),
      'name_id' => $this->samlAuth->getNameId(),
      'name_id_format' => $this->samlAuth->getNameIdFormat(),
    ] as $key => $value) {
      if (isset($value)) {
        $this->tempStoreFactory->set($key, $value);
      }
      else {
        $this->tempStoreFactory->delete($key);
      }
    }
  }

  /**
   * Does processing for the Single Logout Service.
   *
   * @return null|string
   *   Usually returns nothing. May return a URL to redirect to.
   */
  public function sls() {
    // We might at some point check if this code can be abstracted a bit...
    if ($this->config->get('debug_log_in')) {
      if (isset($_GET['SAMLResponse'])) {
        $response = base64_decode($_GET['SAMLResponse']);
        if ($response) {
          $this->logger->debug("SLS received 'SAMLResponse' in GET request (base64 decoded): <pre>@message</pre>", ['@message' => $response]);
        }
        else {
          $this->logger->warning("SLS received 'SAMLResponse' in GET request which could not be base64 decoded: <pre>@message</pre>", ['@message' => $_POST['SAMLResponse']]);
        }
      }
      elseif (isset($_GET['SAMLRequest'])) {
        $response = base64_decode($_GET['SAMLRequest']);
        if ($response) {
          $this->logger->debug("SLS received 'SAMLRequest' in GET request (base64 decoded): <pre>@message</pre>", ['@message' => $response]);
        }
        else {
          $this->logger->warning("SLS received 'SAMLRequest' in GET request which could not be base64 decoded: <pre>@message</pre>", ['@message' => $_POST['SAMLRequest']]);
        }
      }
      else {
        // Not sure if we should be more detailed...
        $this->logger->warning("HTTP request to SLS is not a GET request, or contains no 'SAMLResponse'/'SAMLRequest' parameters.");
      }
    }

    // This call can either set an error condition or throw a
    // \OneLogin_Saml2_Error exception, depending on whether or not we are
    // processing a POST request. Don't catch the exception.
    $url = $this->getSamlAuth()->processSLO(FALSE, NULL, (bool) $this->config->get('security_logout_reuse_sigs'), NULL, TRUE);

    if ($this->config->get('debug_log_saml_in')) {
      // There should be no way we can get here if nether GET parameter is set;
      // if nothing gets logged, that's a bug.
      if (isset($_GET['SAMLResponse'])) {
        $this->logger->debug('SLS received SAML response: <pre>@message</pre>', ['@message' => $this->getSamlAuth()->getLastResponseXML()]);
      }
      elseif (isset($_GET['SAMLRequest'])) {
        $this->logger->debug('SLS received SAML request: <pre>@message</pre>', ['@message' => $this->getSamlAuth()->getLastRequestXML()]);
      }
    }
    // Now look if there were any errors and also throw.
    $errors = $this->getSamlAuth()->getErrors();
    if (!empty($errors)) {
      // We have one or multiple error types / short descriptions, and one
      // 'reason' for the last error.
      throw new RuntimeException('Error(s) encountered during processing of SLS response. Type(s): ' . implode(', ', array_unique($errors)) . '; reason given for last error: ' . $this->getSamlAuth()->getLastErrorReason());
    }

    // Usually we don't get any URL returned. The case in which we do, seems to
    // be something like IdP-initiated logout. Therefore we won't do further
    // processing.
    if (!$url) {
      // Delete private stored session information.
      foreach (['session_index', 'session_expiration'] as $key) {
        $this->tempStoreFactory->delete($key);
      }
      user_logout();
    }

    return $url;
  }

  /**
   * Synchronizes user data with attributes in the SAML request.
   *
   * @param \Drupal\user\UserInterface $account
   *   The Drupal user to synchronize attributes into.
   * @param bool $skip_save
   *   (optional) If TRUE, skip saving the user account.
   */
  public function synchronizeUserAttributes(UserInterface $account, $skip_save = FALSE) {
    // Dispatch a user_sync event.
    $event = new SamlauthUserSyncEvent($account, $this->getAttributes());
    $this->eventDispatcher->dispatch(SamlauthEvents::USER_SYNC, $event);

    if (!$skip_save && $event->isAccountChanged()) {
      $account->save();
    }
  }

  /**
   * Returns all attributes in a SAML response.
   *
   * This method will return valid data after a response is processed (i.e.
   * after samlAuth->processResponse() is called).
   *
   * @return array
   *   An array with all returned SAML attributes..
   */
  public function getAttributes() {
    return $this->getSamlAuth()->getAttributes();
  }

  /**
   * Returns value from a SAML attribute whose name is configured in our module.
   *
   * This method will return valid data after a response is processed (i.e.
   * after samlAuth->processResponse() is called).
   *
   * @param string $config_key
   *   A key in the module's configuration, containing the name of a SAML
   *   attribute.
   *
   * @return mixed|null
   *   The SAML attribute value; NULL if the attribute value, or configuration
   *   key, was not found.
   */
  public function getAttributeByConfig($config_key) {
    $attribute_name = $this->config->get($config_key);
    if ($attribute_name) {
      $attribute = $this->getSamlAuth()->getAttribute($attribute_name);
      if (!empty($attribute[0])) {
        return $attribute[0];
      }
    }
  }

  /**
   * @return bool if a valid user was fetched from the saml assertion this request.
   */
  protected function isAuthenticated() {
    return $this->getSamlAuth()->isAuthenticated();
  }

  /**
   * Returns an initialized Auth class from the SAML Toolkit.
   */
  protected function getSamlAuth() {
    if (!isset($this->samlAuth)) {
      $this->samlAuth = new Auth(static::reformatConfig($this->config));
    }

    return $this->samlAuth;
  }

  /**
   * Returns a configuration array as used by the external library.
   *
   * @param \Drupal\Core\Config\ImmutableConfig $config
   *   The module configuration.
   *
   * @return array
   *   The library configuration array.
   */
  protected static function reformatConfig(ImmutableConfig $config) {
    // Check if we want to load the certificates from a folder. Either folder or
    // cert+key settings should be defined. If both are defined, "folder" is the
    // preferred method and we ignore cert/path values; we don't do more
    // complicated validation like checking whether the cert/key files exist.
    $sp_cert = '';
    $sp_key = '';
    $cert_folder = $config->get('sp_cert_folder');
    if ($cert_folder) {
      // Set the folder so the SAML toolkit knows where to look.
      if (!defined('ONELOGIN_CUSTOMPATH')) {
        define('ONELOGIN_CUSTOMPATH', "$cert_folder/");
      }
    }
    else {
      $sp_cert = $config->get('sp_x509_certificate');
      $sp_key = $config->get('sp_private_key');
    }

    $library_config = [
      'debug' => (bool) $config->get('debug_phpsaml'),
      'sp' => [
        'entityId' => $config->get('sp_entity_id'),
        'assertionConsumerService' => [
          // Try SamlController::createRedirectResponse() if curious for
          // details on why the long chained call is necessary.
          'url' => Url::fromRoute('samlauth.saml_controller_acs', [], ['absolute' => TRUE])->toString(TRUE)->getGeneratedUrl(),
        ],
        'singleLogoutService' => [
          'url' => Url::fromRoute('samlauth.saml_controller_sls', [], ['absolute' => TRUE])->toString(TRUE)->getGeneratedUrl(),
        ],
        'NameIDFormat' => $config->get('sp_name_id_format') ?: NULL,
        'x509cert' => $sp_cert,
        'privateKey' => $sp_key,
      ],
      'idp' => [
        'entityId' => $config->get('idp_entity_id'),
        'singleSignOnService' => [
          'url' => $config->get('idp_single_sign_on_service'),
        ],
        'singleLogoutService' => [
          'url' => $config->get('idp_single_log_out_service'),
        ],
        'x509cert' => $config->get('idp_x509_certificate'),
      ],
      'security' => [
        'authnRequestsSigned' => (bool) $config->get('security_authn_requests_sign'),
        'logoutRequestSigned' => (bool) $config->get('security_logout_requests_sign'),
        'logoutResponseSigned' => (bool) $config->get('security_logout_responses_sign'),
        'wantAssertionsEncrypted' => (bool) $config->get('security_assertions_encrypt'),
        'wantMessagesSigned' => (bool) $config->get('security_messages_sign'),
        'requestedAuthnContext' => (bool) $config->get('security_request_authn_context'),
        'lowercaseUrlencoding' => (bool) $config->get('security_lowercase_url_encoding'),
        'signatureAlgorithm' => $config->get('security_signature_algorithm'),
        // This is the first setting that is TRUE by default AND must be TRUE
        // on existing installations that didn't have the setting before, so
        // it's the first one to get a default value. (If we didn't have the
        // (bool) operator, we wouldn't necessarily need the default - but
        // leaving it out would just invite a bug later on.)
        'wantNameId' => (bool) ($config->get('security_want_name_id') ?? TRUE),
      ],
      'strict' => (bool) $config->get('strict'),
    ];

    // Check for the presence of a multi cert situation.
    $multi = $config->get('idp_cert_type');
    switch ($multi) {
      case "signing":
        $library_config['idp']['x509certMulti'] = [
          'signing' => [
            $config->get('idp_x509_certificate'),
            $config->get('idp_x509_certificate_multi'),
          ],
        ];
        break;

      case "encryption":
        $library_config['idp']['x509certMulti'] = [
          'signing' => [
            $config->get('idp_x509_certificate'),
          ],
          'encryption' => [
            $config->get('idp_x509_certificate_multi'),
          ],
        ];
        break;
    }

    return $library_config;
  }

}