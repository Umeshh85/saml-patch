<?php

namespace Drupal\samlauth\Form;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Path\PathValidatorInterface;
use Drupal\Core\Url;
use Drupal\Core\Utility\Token;
use OneLogin\Saml2\Utils as SamlUtils;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Provides a configuration form for samlauth module settings and IdP/SP info.
 */
class SamlauthConfigureForm extends ConfigFormBase {

  /**
   * The PathValidator service.
   *
   * @var \Drupal\Core\Path\PathValidatorInterface
   */
  protected $pathValidator;

  /**
   * The token service.
   *
   * @var \Drupal\Core\Utility\Token
   */
  protected $token;

  /**
   * Constructs a \Drupal\samlauth\Form\SamlauthConfigureForm object.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The factory for configuration objects.
   * @param \Drupal\Core\Path\PathValidatorInterface $path_validator
   *   The PathValidator service.
   * @param \Drupal\Core\Utility\Token $token
   *   The token service.
   */
  public function __construct(ConfigFactoryInterface $config_factory, PathValidatorInterface $path_validator, Token $token) {
    parent::__construct($config_factory);
    $this->pathValidator = $path_validator;
    $this->token = $token;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('config.factory'),
      $container->get('path.validator'),
      $container->get('token')
    );
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return [
      'samlauth.authentication',
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'samlauth_configure_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $config = $this->config('samlauth.authentication');

    $form['saml_login_logout'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Login / Logout'),
    ];

    // Show note for enabling "log in" or "log out" menu link item.
    if (Url::fromRoute('entity.menu.edit_form', ['menu' => 'account'])->access()) {
      $form['saml_login_logout']['menu_item'] = [
        '#type' => 'markup',
        '#markup' => '<em>' . $this->t('Note: You <a href="@url">may want to enable</a> the "log in" / "log out" menu item and disable the original one.', [
          '@url' => Url::fromRoute('entity.menu.edit_form', ['menu' => 'account'])
            ->toString(),
        ]) . '</em>',
      ];
    }

    $form['saml_login_logout']['login_menu_item_title'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Login menu item title'),
      '#description' => $this->t('The title of the SAML login link. Defaults to "Log in".'),
      '#default_value' => $config->get('login_menu_item_title'),
    ];

    $form['saml_login_logout']['logout_menu_item_title'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Logout menu item title'),
      '#description' => $this->t('The title of the SAML logout link. Defaults to "Log out".'),
      '#default_value' => $config->get('logout_menu_item_title'),
    ];

    $form['saml_login_logout']['drupal_saml_login'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Allow SAML users to log in directly'),
      '#description' => $this->t('Drupal users who have previously logged in through the SAML Identity Provider can also log in through the standard Drupal login screen. (By default, they must always log in through the Identity Provider. This option does not affect Drupal user acounts that are never linked to a SAML login.)'),
      '#default_value' => $config->get('drupal_saml_login'),
    ];

    $form['saml_login_logout']['login_redirect_url'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Login redirect URL'),
      '#description' => $this->t("The default URL to redirect the user to after login. This should be an internal path starting with a slash, or an absolute URL. Defaults to the logged-in user's account page."),
      '#default_value' => $config->get('login_redirect_url'),
    ];

    $form['saml_login_logout']['logout_redirect_url'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Logout redirect URL'),
      '#description' => $this->t('The default URL to redirect the user to after logout. This should be an internal path starting with a slash, or an absolute URL. Defaults to the front page.'),
      '#default_value' => $config->get('logout_redirect_url'),
    ];

    $form['service_provider'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Service Provider'),
    ];

    $form['service_provider']['config_info'] = [
      '#theme' => 'item_list',
      '#items' => [
        $this->t('Metadata URL') . ': ' . \Drupal::urlGenerator()->generateFromRoute('samlauth.saml_controller_metadata', [], ['absolute' => TRUE]),
        $this->t('Assertion Consumer Service') . ': ' . Url::fromRoute('samlauth.saml_controller_acs', [], ['absolute' => TRUE])->toString(),
        $this->t('Single Logout Service') . ': ' . Url::fromRoute('samlauth.saml_controller_sls', [], ['absolute' => TRUE])->toString(),
      ],
      '#empty' => [],
      '#list_type' => 'ul',
      '#suffix' => $this->t("The info advertised at the metadata URL are influenced by this configuration section, as well as by some more advanced SAML message options below. Those options often don't matter for getting SAML login into Drupal to work."),
    ];

    $form['service_provider']['sp_entity_id'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Entity ID'),
      '#description' => $this->t('The identifier representing the SP.'),
      '#default_value' => $config->get('sp_entity_id'),
    ];

    $cert_folder = $config->get('sp_cert_folder');
    $sp_x509_certificate = $config->get('sp_x509_certificate');
    $sp_private_key = $config->get('sp_private_key');

    $form['service_provider']['sp_cert_type'] = [
      '#type' => 'select',
      '#title' => $this->t('Type of configuration to save for the certificates'),
      '#required' => TRUE,
      '#options' => [
        'folder' => $this->t('Folder name'),
        'fields' => $this->t('Cert/key value'),
      ],
      // Prefer folder over certs, like SamlService::reformatConfig(), but if
      // both are empty then default to folder here.
      '#default_value' => $cert_folder || (!$sp_x509_certificate && !$sp_private_key) ? 'folder' : 'fields',
    ];

    $form['service_provider']['sp_x509_certificate'] = [
      '#type' => 'textarea',
      '#title' => $this->t('x509 Certificate'),
      '#description' => $this->t("Public x509 certificate for the SP; line breaks and '-----BEGIN/END' lines are optional."),
      '#default_value' => $this->formatKeyOrCert($config->get('sp_x509_certificate'), TRUE),
      '#states' => [
        'visible' => [
          ':input[name="sp_cert_type"]' => ['value' => 'fields'],
        ],
      ],
    ];

    $form['service_provider']['sp_private_key'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Private Key'),
      '#description' => $this->t("Private key for the SP; line breaks and '-----BEGIN/END' lines are optional."),
      '#default_value' => $this->formatKeyOrCert($config->get('sp_private_key'), TRUE, TRUE),
      '#states' => [
        'visible' => [
          ':input[name="sp_cert_type"]' => ['value' => 'fields'],
        ],
      ],
    ];

    $form['service_provider']['sp_cert_folder'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Certificate folder'),
      '#description' => $this->t('This folder must contain a certs/ subfolder containing certs/sp.key (private key) and certs/sp.crt (public cert) files. The names of the subfolder and files are mandated by the external SAML Toolkit library.'),
      '#default_value' => $cert_folder,
      '#states' => [
        'visible' => [
          ':input[name="sp_cert_type"]' => ['value' => 'folder'],
        ],
      ],
    ];

    $form['identity_provider'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Identity Provider'),
    ];

    // @TODO: Allow a user to automagically populate this by providing a metadata URL for the IdP.
    //    $form['identity_provider']['idp_metadata_url'] = [
    //      '#type' => 'url',
    //      '#title' => $this->t('Metadata URL'),
    //      '#description' => $this->t('URL of the XML metadata for the identity provider'),
    //      '#default_value' => $config->get('idp_metadata_url'),
    //    ];
    $form['identity_provider']['idp_entity_id'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Entity ID'),
      '#description' => $this->t('The identifier representing the IdP.'),
      '#default_value' => $config->get('idp_entity_id'),
    ];

    $form['identity_provider']['idp_single_sign_on_service'] = [
      '#type' => 'url',
      '#title' => $this->t('Single Sign On Service'),
      '#description' => $this->t('URL where the SP will direct authentication requests.'),
      '#default_value' => $config->get('idp_single_sign_on_service'),
    ];

    $form['identity_provider']['idp_single_log_out_service'] = [
      '#type' => 'url',
      '#title' => $this->t('Single Logout Service'),
      '#description' => $this->t('URL where the SP will direct logout requests.'),
      '#default_value' => $config->get('idp_single_log_out_service'),
    ];

    $form['identity_provider']['idp_change_password_service'] = [
      '#type' => 'url',
      '#title' => $this->t('Change Password Service'),
      '#description' => $this->t('URL where users will be directed to change their password.'),
      '#default_value' => $config->get('idp_change_password_service'),
    ];

    $form['identity_provider']['idp_cert_type'] = [
      '#type' => 'select',
      '#title' => $this->t('Single/Multi Cert'),
      '#required' => TRUE,
      '#options' => [
        'single' => $this->t('Single Cert'),
        'signing' => $this->t('Key Rollover Phase'),
        'encryption' => $this->t('Unique Signing/Encryption'),
      ],
      '#default_value' => $config->get('idp_cert_type') ? $config->get('idp_cert_type') : 'single',
    ];

    $form['identity_provider']['idp_x509_certificate'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Primary x509 Certificate'),
      '#description' => $this->t("Public x509 certificate of the IdP; line breaks and '-----BEGIN/END' lines are optional. (The external SAML Toolkit library does not allow configuring this as a separate file.)"),
      '#default_value' => $this->formatKeyOrCert($config->get('idp_x509_certificate'), TRUE),
    ];

    $form['identity_provider']['idp_x509_certificate_multi'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Secondary x509 Certificate'),
      '#description' => $this->t('Secondary public x509 certificate of the IdP. This is a signing key if using "Key Rollover Phase" and an encryption key if using "Unique Signing/Encryption."'),
      '#default_value' => $this->formatKeyOrCert($config->get('idp_x509_certificate_multi'), TRUE),
      '#states' => [
        'invisible' => [
          ':input[name="idp_cert_type"]' => ['value' => 'single'],
        ],
      ],
    ];

    $form['user_info'] = [
      '#title' => $this->t('User Info and Syncing'),
      '#type' => 'fieldset',
    ];

    $form['user_info']['unique_id_attribute'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Unique ID attribute'),
      '#description' => $this->t("A SAML attribute whose value is unique per user and does not change over time. Its value is stored by Drupal and linked to the Drupal user that is logged in. (In principle, a non-transient NameID could also be used for this value; the SAML Authentication module does not support this yet.)<br>Example: <em>eduPersonPrincipalName</em> or <em>eduPersonTargetedID</em>"),
      '#default_value' => $config->get('unique_id_attribute') ?: 'eduPersonTargetedID',
    ];

    $form['user_info']['map_users'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Attempt to link SAML data to existing local users'),
      '#description' => $this->t('If the unique ID in the SAML assertion is not linked to a Drupal user, and the name / e-mail attribute matches an existing non-linked Drupal user, that user will be linked and logged in. (By default, a new user is created with the same data depending on the next option - which may result in an error about a duplicate or missing user.)'),
      '#default_value' => $config->get('map_users'),
    ];

    $form['user_info']['create_users'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Create users from SAML data'),
      '#description' => $this->t('If data in the SAML assertion is not linked to a Drupal user, a new user is created using the name / e-mail attributes from the response.'),
      '#default_value' => $config->get('create_users'),
    ];

    $form['user_info']['sync_name'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Synchronize user name on every login'),
      '#default_value' => $config->get('sync_name'),
      '#description' => $this->t('The name attribute in the SAML assertion will be propagated to the linked Drupal user on every login. (By default, the Drupal user name is not changed after user creation.)'),
    ];

    $form['user_info']['sync_mail'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Synchronize email address on every login'),
      '#default_value' => $config->get('sync_mail'),
      '#description' => $this->t('The email attribute in the SAML assertion will be propagated to the linked Drupal user on every login. (By default, the Drupal user email is not changed after user creation.)'),
    ];

    $form['user_info']['user_name_attribute'] = [
      '#type' => 'textfield',
      '#title' => $this->t('User name attribute'),
      '#description' => $this->t('When users are linked / created, this field specifies which SAML attribute should be used for the Drupal user name.<br />Example: <em>cn</em> or <em>eduPersonPrincipalName</em>'),
      '#default_value' => $config->get('user_name_attribute'),
      '#states' => [
        'invisible' => [
          ':input[name="map_users"]' => ['checked' => FALSE],
          ':input[name="create_users"]' => ['checked' => FALSE],
          ':input[name="sync_name"]' => ['checked' => FALSE],
        ],
      ],
    ];

    $form['user_info']['user_mail_attribute'] = [
      '#type' => 'textfield',
      '#title' => $this->t('User email attribute'),
      '#description' => $this->t('When users are linked / created, this field specifies which SAML attribute should be used for the Drupal email address.<br />Example: <em>mail</em>'),
      '#default_value' => $config->get('user_mail_attribute'),
      '#states' => [
        'invisible' => [
          ':input[name="map_users"]' => ['checked' => FALSE],
          ':input[name="create_users"]' => ['checked' => FALSE],
          ':input[name="sync_mail"]' => ['checked' => FALSE],
        ],
      ],
    ];

    $form['security'] = [
      '#title' => $this->t('SAML Message Construction'),
      '#type' => 'fieldset',
    ];

    $form['security']['security_authn_requests_sign'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Sign authentication requests'),
      '#description' => $this->t('Requests sent to the Single Sign-On Service of the IdP will include a signature.'),
      '#default_value' => $config->get('security_authn_requests_sign'),
    ];

    $form['security']['security_logout_requests_sign'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Sign logout requests'),
      '#description' => $this->t('Requests sent to the Single Logout Service of the IdP will include a signature.'),
      '#default_value' => $config->get('security_logout_requests_sign'),
    ];

    $form['security']['security_logout_responses_sign'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Sign logout responses'),
      '#description' => $this->t('Responses sent back to the IdP will include a signature.'),
      '#default_value' => $config->get('security_logout_responses_sign'),
    ];

    $form['security']['security_signature_algorithm'] = [
      '#type' => 'select',
      '#title' => $this->t('Signature algorithm'),
      // The first option is the library default.
      '#options' => [
        'http://www.w3.org/2000/09/xmldsig#rsa-sha1' => 'RSA-sha1',
        'http://www.w3.org/2000/09/xmldsig#hmac-sha1' => 'HMAC-sha1',
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' => 'sha256',
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384' => 'sha384',
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512' => 'sha512',
      ],
      '#description' => $this->t('Algorithm used in the signing process.'),
      '#default_value' => $config->get('security_signature_algorithm'),
      '#states' => [
        'invisible' => [
          ':input[name="security_authn_requests_sign"]' => ['checked' => FALSE],
          ':input[name="security_logout_requests_sign"]' => ['checked' => FALSE],
          ':input[name="security_logout_responses_sign"]' => ['checked' => FALSE],
        ],
      ],
    ];

    $form['security']['security_request_authn_context'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Specify authentication context'),
      '#description' => $this->t('Specify that only a subset of authentication methods available at the IdP should be used. (If checked, the "PasswordProtectedTransport" authentication method is specified, which is default behavior for the SAML Toolkit library. If other restrictions are needed, we should change the checkbox to a text input.)'),
      '#default_value' => $config->get('security_request_authn_context'),
    ];

    $form['security']['request_set_name_id_policy'] = [
      '#type' => 'checkbox',
      '#title' => t('Specify NameID policy'),
      '#description' => t('A NameIDPolicy element is added in authentication requests. This is default behavior for the SAML Toolkit library, but may be unneeded. If checked, "NameID Format" may need to be specified too. If unchecked, the "Require NameID" checkbox may need to be unchecked too.'),
      // This is one of the few checkboxes that must be TRUE on existing
      // installations where the checkbox didn't exist before (in older module
      // versions). Others get their default only from the config/install file.
      '#default_value' => $config->get('request_set_name_id_policy') ?? TRUE,
    ];

    $form['security']['sp_name_id_format'] = [
      '#type' => 'textfield',
      '#title' => $this->t('NameID Format'),
      '#description' => $this->t('The format for the NameID attribute to request from the identity provider. If "Specify NameID policy" is unchecked, this value is not included in authentication requests but is still included in the SP metadata. Some common formats (with "unspecified" being the default):<br>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified<br>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress<br>urn:oasis:names:tc:SAML:2.0:nameid-format:transient<br>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'),
      '#default_value' => $config->get('sp_name_id_format'),
    ];

    // Just mucking around with grouping of options a bit...
    $form['responses'] = [
      '#title' => $this->t('SAML Message Validation'),
      '#type' => 'fieldset',
    ];
    $group = isset($form['responses']) ? 'responses' : 'security';

    $form[$group]['security_want_name_id'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Require NameID'),
      '#description' => $this->t('The login response from the IdP must contain a NameID attribute. (This is default behavior for the SAML Toolkit library, but the SAML Authentication module does not use NameID values, so it seems this can be unchecked safely.)'),
      // This is one of the few checkboxes that must be TRUE on existing
      // installations where the checkbox didn't exist before (in older module
      // versions). Others get their default only from the config/install file.
      '#default_value' => $config->get('security_want_name_id') ?? TRUE,
    ];

    // This option's default value is FALSE but according to the SAML spec,
    // signing parameters should always be retrieved from the original request
    // instead of recalculated. (As argued in e.g.
    // https://github.com/onelogin/php-saml/issues/130.) The 'TRUE' option
    // (which was implemented in #6a828bf, as a result of
    // https://github.com/onelogin/php-saml/pull/37) reads the parameters from
    // $_SERVER['REQUEST'] but unfortunately this is not always populated in
    // all PHP/webserver configurations. IMHO the code should have a fallback
    // to other 'self encoding' methods if $_SERVER['REQUEST'] is empty; I see
    // no downside to that and it would enable us to always set TRUE / get rid
    // of this option in a future version of the SAML Toolkit library.
    // @todo file PR against SAML toolkit; note it in https://www.drupal.org/project/samlauth/issues/3131028
    $form[$group]['security_logout_reuse_sigs'] = [
      '#type' => 'checkbox',
      '#title' => $this->t("Retrieve logout signature parameters from \$_SERVER['REQUEST']"),
      '#description' => $this->t('Validation of logout requests/responses can fail on some IdPs (among others, ADFS) if this option is not set. This happens independently of the  "Strict validation" option.'),
      '#default_value' => $config->get('security_logout_reuse_sigs'),
    ];

    $form[$group]['strict'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Strict validation of responses'),
      '#description' => $this->t('Validation failures (partly based on the next options) will cause the SAML conversation to be terminated. In production environments, this <em>must</em> be set.'),
      '#default_value' => $config->get('strict'),
    ];

    $form[$group]['security_messages_sign'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Require messages to be signed'),
      '#description' => $this->t('Responses (and logout requests) from the IdP are expected to be signed.'),
      '#default_value' => $config->get('security_messages_sign'),
      '#states' => [
        'disabled' => [
          ':input[name="strict"]' => ['checked' => FALSE],
        ],
      ],
    ];

    $form[$group]['security_assertions_encrypt'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Require assertions to be encrypted'),
      // The metadata changes if wantAssertionsEncrypted OR wantNameIdEncrypted
      // are set. But we don't have wantNameIdEncrypted yet, so we'll describe
      // this option as the way to change the metadata.
      '#description' => $this->t("Assertion elements in responses from the IdP are expected to be encrypted. (When strict validation is turned off, this option still has the effect of specifying this expectation in the SP metadata.)"),
      '#default_value' => $config->get('security_assertions_encrypt'),
    ];

    $form['other'] = [
      '#title' => $this->t('Other'),
      '#type' => 'fieldset',
    ];

    $form['other']['use_proxy_headers'] = array(
      '#type' => 'checkbox',
      '#title' => $this->t("Use 'X-Forwarded-*' headers."),
      '#description' => $this->t("The SAML Toolkit will use 'X-Forwarded-*' HTTP headers (if present) for constructing/identifying the SP URL in sent/received messages. This is likely necessary if your SP is behind a reverse proxy, and your Drupal installation is not already <a href=\"https://www.drupal.org/node/425990\" target=\"_blank\">dealing with this</a>."),
      '#default_value' => $config->get('use_proxy_headers'),
    );

    $form['debugging'] = [
      '#title' => $this->t('Debugging'),
      '#type' => 'fieldset',
    ];

    // This option has effect on signing of (login + logout) requests and
    // logout responses. It's badly named (in the SAML Toolkit;
    // "lowercaseUrlencoding") because there has never been any connection to
    // the case of URL-encoded strings. The only thing this does is use
    // rawurlencode() rather than urlencode() for URL encoding of signatures
    // sent to the IdP. This option arguably shouldn't even exist because the
    // use of urlencode() arguably is a bug that should just have been fixed.
    // (The name "lowercaseUrlencoding" seems to come from a mistake: it
    // originates from https://github.com/onelogin/python-saml/pull/144/files,
    // a PR for the signature validation code for incoming messages, which was
    // then mentioned in https://github.com/onelogin/php-saml/issues/136.
    // However, the latter / this option is about signature generation for
    // outgoing messages. Validation concerns different code, and is influenced
    // by the 'security_logout_reuse_sigs' option below, which has its own
    // issues.) This means that the default value should actually be TRUE.
    // @todo file PR against SAML toolkit; note it in https://www.drupal.org/project/samlauth/issues/3131028
    // @TODO change default to TRUE; amend description (and d.o issue, and README
    $form['debugging']['security_lowercase_url_encoding'] = [
      '#type' => 'checkbox',
      '#title' => $this->t("'Raw' encoding of SAML messages"),
      '#description' => $this->t("If there is ever a reason to turn this option off, a bug report is greatly appreciated. (The module author believes this option is unnecessary and plans for a PR to the SAML Toolkit to re-document it / phase it out. If you installed this module prior to 8.x-3.0-alpha2 and this option is turned off already, that's fine - changing it should make no difference.)"),
      '#default_value' => $config->get('security_lowercase_url_encoding'),
      '#states' => [
        'disabled' => [
          ':input[name="security_authn_requests_sign"]' => ['checked' => FALSE],
          ':input[name="security_logout_requests_sign"]' => ['checked' => FALSE],
          ':input[name="security_logout_responses_sign"]' => ['checked' => FALSE],
        ],
      ],
    ];

    $form['debugging']['debug_display_error_details'] = [
      '#type' => 'checkbox',
      '#title' => $this->t("Show detailed errors to the user"),
      '#description' => $this->t("This can help testing until SAML login/logout works. (Technical details about failed SAML login/logout are only logged to watchdog by default, to prevent exposing information about a misconfigured system / because it's unlikely they are useful.)"),
      '#default_value' => $config->get('debug_display_error_details'),
    ];

    $form['debugging']['debug_log_saml_out'] = [
      '#type' => 'checkbox',
      '#title' => $this->t("Log outgoing SAML messages"),
      '#description' => $this->t("Log messages which the SAML Toolkit 'sends' to the IdP (usually via the web browser through a HTTP redirect, as part of the URL)."),
      '#default_value' => $config->get('debug_log_saml_out'),
    ];

    $form['debugging']['debug_log_saml_in'] = [
      '#type' => 'checkbox',
      '#title' => $this->t("Log incoming SAML messages"),
      '#description' => $this->t("Log SAML responses (and logout requests) received by the ACS/SLS endpoints."),
      '#default_value' => $config->get('debug_log_saml_in'),
    ];

    $form['debugging']['debug_log_in'] = [
      '#type' => 'checkbox',
      '#title' => $this->t("Log incoming messages before validation"),
      '#description' => $this->t("Log supposed SAML messages received by the ACS/SLS endpoints before validating them as XML. If the other option logs nothing, this still might, but the logged contents may make less sense."),
      '#default_value' => $config->get('debug_log_in'),
    ];

    $form['debugging']['debug_phpsaml'] = [
      '#type' => 'checkbox',
      '#title' => $this->t("Enable debugging in SAML Toolkit library"),
      '#description' => $this->t("The exact benefit is unclear; as of library v3.4, this prints out certain validation errors to STDOUT / syslog, many of which would also be reported by other means. However, that might change..."),
      '#default_value' => $config->get('debug_phpsaml'),
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    parent::validateForm($form, $form_state);
    // @TODO: Validate cert. Might be able to just openssl_x509_parse().
    // Validate login/logout redirect URLs.
    $login_url_path = $form_state->getValue('login_redirect_url');
    if ($login_url_path) {
      $login_url_path = $this->token->replace($login_url_path);
      $login_url = $this->pathValidator->getUrlIfValidWithoutAccessCheck($login_url_path);
      if (!$login_url) {
        $form_state->setErrorByName('login_redirect_url', $this->t('The Login Redirect URL is not a valid path.'));
      }
    }
    $logout_url_path = $form_state->getValue('logout_redirect_url');
    if ($logout_url_path) {
      $logout_url_path = $this->token->replace($logout_url_path);
      $logout_url = $this->pathValidator->getUrlIfValidWithoutAccessCheck($logout_url_path);
      if (!$logout_url) {
        $form_state->setErrorByName('logout_redirect_url', $this->t('The Logout Redirect URL is not a valid path.'));
      }
    }

    // Validate certs folder. Don't allow the user to save an empty folder; if
    // they want to save incomplete config data, they can switch to 'fields'.
    $sp_cert_type = $form_state->getValue('sp_cert_type');
    $sp_cert_folder = $this->fixFolderPath($form_state->getValue('sp_cert_folder'));
    if ($sp_cert_type == 'folder') {
      if (empty($sp_cert_folder)) {
        $form_state->setErrorByName('sp_cert_folder', $this->t('@name field is required.', ['@name' => $form['service_provider']['sp_cert_folder']['#title']]));
      }
      elseif (!file_exists($sp_cert_folder . '/certs/sp.key') || !file_exists($sp_cert_folder . '/certs/sp.crt')) {
        $form_state->setErrorByName('sp_cert_folder', $this->t('The Certificate folder does not contain the required certs/sp.key or certs/sp.crt files.'));
      }
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    parent::submitForm($form, $form_state);

    // Only store variables related to the sp_cert_type value. (If the user
    // switched from fields to folder, the cert/key values always get cleared
    // so no unused security sensitive data gets saved in the database.)
    $sp_cert_type = $form_state->getValue('sp_cert_type');
    $sp_x509_certificate = '';
    $sp_private_key = '';
    $sp_cert_folder = '';
    if ($sp_cert_type == 'folder') {
      $sp_cert_folder = $this->fixFolderPath($form_state->getValue('sp_cert_folder'));
    }
    else {
      $sp_x509_certificate =  $this->formatKeyOrCert($form_state->getValue('sp_x509_certificate'), FALSE);
      $sp_private_key =  $this->formatKeyOrCert($form_state->getValue('sp_private_key'), FALSE, TRUE);
    }

    $this->config('samlauth.authentication')
      ->set('login_menu_item_title', $form_state->getValue('login_menu_item_title'))
      ->set('logout_menu_item_title', $form_state->getValue('logout_menu_item_title'))
      ->set('drupal_saml_login', $form_state->getValue('drupal_saml_login'))
      ->set('login_redirect_url', $form_state->getValue('login_redirect_url'))
      ->set('logout_redirect_url', $form_state->getValue('logout_redirect_url'))
      ->set('sp_entity_id', $form_state->getValue('sp_entity_id'))
      ->set('sp_name_id_format', $form_state->getValue('sp_name_id_format'))
      ->set('sp_x509_certificate', $sp_x509_certificate)
      ->set('sp_private_key', $sp_private_key)
      ->set('sp_cert_folder', $sp_cert_folder)
      ->set('idp_entity_id', $form_state->getValue('idp_entity_id'))
      ->set('idp_single_sign_on_service', $form_state->getValue('idp_single_sign_on_service'))
      ->set('idp_single_log_out_service', $form_state->getValue('idp_single_log_out_service'))
      ->set('idp_change_password_service', $form_state->getValue('idp_change_password_service'))
      ->set('idp_cert_type', $form_state->getValue('idp_cert_type'))
      ->set('idp_x509_certificate', $this->formatKeyOrCert($form_state->getValue('idp_x509_certificate'), FALSE))
      ->set('idp_x509_certificate_multi', $this->formatKeyOrCert($form_state->getValue('idp_x509_certificate_multi'), FALSE))
      ->set('unique_id_attribute', $form_state->getValue('unique_id_attribute'))
      ->set('map_users', $form_state->getValue('map_users'))
      ->set('create_users', $form_state->getValue('create_users'))
      ->set('sync_name', $form_state->getValue('sync_name'))
      ->set('sync_mail', $form_state->getValue('sync_mail'))
      ->set('user_name_attribute', $form_state->getValue('user_name_attribute'))
      ->set('user_mail_attribute', $form_state->getValue('user_mail_attribute'))
      ->set('security_authn_requests_sign', $form_state->getValue('security_authn_requests_sign'))
      ->set('security_logout_requests_sign', $form_state->getValue('security_logout_requests_sign'))
      ->set('security_logout_responses_sign', $form_state->getValue('security_logout_responses_sign'))
      ->set('security_assertions_encrypt', $form_state->getValue('security_assertions_encrypt'))
      ->set('security_lowercase_url_encoding', $form_state->getValue('security_lowercase_url_encoding'))
      ->set('security_messages_sign', $form_state->getValue('security_messages_sign'))
      ->set('request_set_name_id_policy', $form_state->getValue('request_set_name_id_policy'))
      ->set('security_want_name_id', $form_state->getValue('security_want_name_id'))
      ->set('security_logout_reuse_sigs', $form_state->getValue('security_logout_reuse_sigs'))
      ->set('security_request_authn_context', $form_state->getValue('security_request_authn_context'))
      ->set('security_signature_algorithm', $form_state->getValue('security_signature_algorithm'))
      ->set('strict', $form_state->getValue('strict'))
      ->set('use_proxy_headers', $form_state->getValue('use_proxy_headers'))
      ->set('debug_display_error_details', $form_state->getValue('debug_display_error_details'))
      ->set('debug_log_saml_out', $form_state->getValue('debug_log_saml_out'))
      ->set('debug_log_saml_in', $form_state->getValue('debug_log_saml_in'))
      ->set('debug_log_in', $form_state->getValue('debug_log_in'))
      ->set('debug_phpsaml', $form_state->getValue('debug_phpsaml'))
      ->save();
  }

  /**
   * Format a long string in PEM format, or remove PEM format.
   *
   * Our configuration stores unformatted key/cert values, which is what we
   * would get from SAML metadata and what the SAML toolkit expects. But
   * displaying them formatted in a textbox is better for humans, and also
   * allows us to paste PEM-formatted values (as well as unformatted) into the
   * textbox and not have to remove all the newlines manually, if we got them
   * delivered this way.
   *
   * The side effect is that certificates/keys are re--un-formatted on every
   * save operation, but that should be OK.
   *
   * @param string|null $value
   *   A certificate or private key, either with or without head/footer.
   * @param bool $heads
   *   True to format and include head and footer; False to remove them and
   *   return one string without spaces / line breaks.
   * @param bool $key
   *   (optional) True if this is a private key rather than a certificate.
   *
   * @return string $rsaKey Formatted private key
   */
  protected function formatKeyOrCert($value, $heads, $key = FALSE) {
    if (is_string($value)) { //@TODO FIX LIKELY BUG test
      $value = $key ?
        SamlUtils::formatPrivateKey($value, $heads) :
        SamlUtils::formatCert($value, $heads);
    }
    return $value;
  }

  /**
   * Remove trailing slash from a folder name, to unify config values.
   */
  protected function fixFolderPath($path) {
    if ($path) {
      $path = rtrim($path, '/');
    }
    return $path;
  }

}
