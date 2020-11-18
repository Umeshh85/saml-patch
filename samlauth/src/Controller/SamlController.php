<?php

namespace Drupal\samlauth\Controller;

use Exception;
use Drupal\samlauth\SamlService;
use Drupal\samlauth\UserVisibleException;
use Drupal\Component\Utility\UrlHelper;
use Drupal\Core\Cache\CacheableResponse;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Path\PathValidatorInterface;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Drupal\Core\Url;
use Drupal\Core\Utility\Error;
use Drupal\Core\Utility\Token;
use OneLogin\Saml2\Utils;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Returns responses for samlauth module routes.
 */
class SamlController extends ControllerBase {

  /**
   * The samlauth SAML service.
   *
   * @var \Drupal\samlauth\SamlService
   */
  protected $saml;

  /**
   * The request stack.
   *
   * @var \Symfony\Component\HttpFoundation\RequestStack
   */
  protected $requestStack;

  /**
   * A configuration object containing samlauth settings.
   *
   * @var \Drupal\Core\Config\ImmutableConfig
   */
  protected $config;

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
   * Constructor for Drupal\samlauth\Controller\SamlController.
   *
   * @param \Drupal\samlauth\SamlService $saml
   *   The samlauth SAML service.
   * @param \Symfony\Component\HttpFoundation\RequestStack $request_stack
   *   The request stack.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   * @param \Drupal\Core\Path\PathValidatorInterface $path_validator
   *   The PathValidator service.
   * @param \Drupal\Core\Utility\Token $token
   *   The token service.
   */
  public function __construct(SamlService $saml, RequestStack $request_stack, ConfigFactoryInterface $config_factory, PathValidatorInterface $path_validator, Token $token) {
    $this->saml = $saml;
    $this->requestStack = $request_stack;
    $this->config = $config_factory->get('samlauth.authentication');
    $this->pathValidator = $path_validator;
    $this->token = $token;
  }

  /**
   * Factory method for use by dependency injection container.
   *
   * @param \Symfony\Component\DependencyInjection\ContainerInterface $container
   *
   * @return static
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('samlauth.saml'),
      $container->get('request_stack'),
      $container->get('config.factory'),
      $container->get('path.validator'),
      $container->get('token')
    );
  }

  /**
   * Initiates a SAML2 authentication flow.
   *
   * This route does not log us in (yet); it should redirect to the Login
   * service on the IdP, which should be redirecting back to our ACS endpoint
   * after authenticating the user.
   *
   * @return \Drupal\Core\Routing\TrustedRedirectResponse
   */
  public function login() {
    try {
      $url = $this->saml->login($this->getUrlFromDestination());
    }
    catch (Exception $e) {
      $this->handleException($e, 'initiating SAML login');
      $url = Url::fromRoute('<front>');
    }

    // This response redirects to an external URL in all/common cases. We count
    // on the routing.yml to specify that it's not cacheable.
    return $this->createRedirectResponse($url, TRUE);
  }

  /**
   * Initiates a SAML2 logout flow.
   *
   * This route does not log us out (yet); it should redirect to the SLS
   * service on the IdP, which should be redirecting back to our SLS endpoint.
   *
   * @return \Drupal\Core\Routing\TrustedRedirectResponse
   */
  public function logout() {
    try {
      $url = $this->saml->logout($this->getUrlFromDestination());
    }
    catch (Exception $e) {
      $this->handleException($e, 'initiating SAML logout');
      $url = Url::fromRoute('<front>');
    }

    // This response redirects to an external URL in all/common cases. We count
    // on the routing.yml to specify that it's not cacheable.
    return $this->createRedirectResponse($url, TRUE);
  }

  /**
   * Displays service provider metadata XML for iDP autoconfiguration.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   */
  public function metadata() {
    try {
      $metadata = $this->saml->getMetadata();
    }
    catch (Exception $e) {
      $this->handleException($e, 'processing SAML SP metadata');
      // This response caused by an error condition must not be cacheable.
      return $this->createRedirectResponse(Url::fromRoute('<front>'));
    }

    // The metadata is a 'regular' response and should be cacheable.
    // @todo debugging option: make it not cacheable.
    return new CacheableResponse($metadata, 200, ['Content-Type' => 'text/xml']);
  }

  /**
   * Performs the Attribute Consumer Service.
   *
   * This is usually the second step in the authentication flow; the Login
   * service on the IdP should redirect (or: execute a POST request to) here.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   */
  public function acs() {
    try {
      $this->saml->acs();
      $url = $this->getRedirectUrlAfterProcessing(TRUE);
    }
    catch (Exception $e) {
      $this->handleException($e, 'processing SAML authentication response');
      $url = Url::fromRoute('<front>');
    }

    return $this->createRedirectResponse($url);
  }

  /**
   * Performs the Single Logout Service.
   *
   * This is usually the second step in the logout flow; the SLS service on the
   * IdP should redirect here.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   */
  public function sls() {
    try {
      $url = $this->saml->sls();
      if (!$url) {
        $url = $this->getRedirectUrlAfterProcessing();
      }
    }
    catch (Exception $e) {
      $this->handleException($e, 'processing SAML single-logout response');
      $url = Url::fromRoute('<front>');
    }

    return $this->createRedirectResponse($url);
  }

  /**
   * Redirects to the 'Change Password' service.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   */
  public function changepw() {
    $url = $this->config->get('idp_change_password_service');
    return $this->createRedirectResponse($url);
  }

  /**
   * Constructs a full URL from the 'destination' parameter.
   *
   * This is only considered suitable for feeding a URL string into php-saml's
   * login() / logout() methods (or anything that does not care about cache
   * contexts) because we explicitly unset the destination parameter and
   * discard cacheability metadata generated along with the URL.
   *
   * (PSA for unsuspecting developers: A plain Url::toString() call performs
   * cacheability related actions invisibly in the background, which are needed
   * for outputting a URL as part of a rendered page, but which are likely to
   * cause hard to trace exceptions to be thrown in other cases. I suspect this
   * magic behavior was initially designed not to happen always; it only
   * happens when the current code is executing in a 'render context'. However,
   * Drupal creates a 'render context' super early in the HTTP stack, so in
   * practice all Url::toString() calls cause this behavior. More info:
   * #2630808 / #2638686 / https://www.lullabot.com/articles/early-rendering-a-lesson-in-debugging-drupal-8.)
   *
   * @return string|null
   *   The full absolute URL (i.e. our hostname plus the path in the destination
   *   parameter), or NULL if no destination parameter was given. This value is
   *   tuned to what login() / logout() expect for an input argument.
   *
   * @throws \RuntimeException
   *   If the destination is disallowed.
   */
  protected function getUrlFromDestination() {
    $destination_url = NULL;
    $request_query_parameters = $this->requestStack->getCurrentRequest()->query;
    $destination = $request_query_parameters->get('destination');
    if ($destination) {
      if (UrlHelper::isExternal($destination)) {
        // Disallow redirecting to an external URL after we log in.
        throw new \RuntimeException("Destination URL query parameter must not be external: $destination");
      }
      // The destination parameter is relative by convention but fromUserInput()
      // requires it to start with '/'. (Note '#' and '?' don't make sense here
      // because that would be expanded to the current URL, which is saml/*.)
      if (strpos($destination, '/') !== 0) {
        $destination = "/$destination";
      }
      // See the PSA in the PHPDoc. Details: toString(TRUE) returns an object
      // which contains cacheability metadata (rather than storing it /
      // 'bubbling it up' into an invisible render context in the background,
      // which would cause an exception to be thrown by a caller). We discard
      // it (and only use the URL string) because we don't render or cache
      // anything; we only pass the URL to the SAML toolkit.
      $destination_url = Url::fromUserInput($destination)->setAbsolute()->toString(TRUE)->getGeneratedUrl();

      // After we return from this controller, Drupal immediately redirects to
      // the path set in the 'destination' parameter (for the current URL being
      // handled). We want to always redirect to the IdP instead (and only use
      // $destination_url after the user gets redirected back here), so remove
      // the parameter.
      $request_query_parameters->remove('destination');
    }

    return $destination_url;
  }

  /**
   * Returns a URL to redirect to.
   *
   * This should be called only after successfully processing an ACS/logout
   * response.
   *
   * @param bool $logged_in
   *   (optional) TRUE if an ACS request was just processed.
   *
   * @return \Drupal\Core\Url
   *   The URL to redirect to.
   */
  protected function getRedirectUrlAfterProcessing($logged_in = FALSE) {
    $relay_state = $this->requestStack->getCurrentRequest()->get('RelayState');
    if ($relay_state) {
      // We should be able to trust the RelayState parameter at this point
      // because the response from the IdP was verified. Only validate general
      // syntax.
      if (!UrlHelper::isValid($relay_state, TRUE)) {
        $this->getLogger('samlauth')->error('Invalid RelayState parameter found in request: @relaystate', ['@relaystate' => $relay_state]);
      }
      // The SAML toolkit set a default RelayState to itself (saml/log(in|out))
      // when starting the process; ignore this value.
      elseif (strpos($relay_state, Utils::getSelfURLhost() . '/saml/') !== 0) {
        $url = $relay_state;
      }
    }

    if (empty($url)) {
      // If no url was specified, we check if it was configured.
      $url = $this->config->get($logged_in ? 'login_redirect_url' : 'logout_redirect_url');
    }

    if ($url) {
      $url = $this->token->replace($url);
      // We don't check access here. If a URL was explicitly specified, we
      // prefer returning a 403 over silently redirecting somewhere else.
      $url_object = $this->pathValidator->getUrlIfValidWithoutAccessCheck($url);
      if (empty($url_object)) {
        $type = $logged_in ? 'Login' : 'Logout';
        $this->getLogger('samlauth')->warning("The $type Redirect URL is not a valid path; falling back to default.");
      }
    }

    if (empty($url_object)) {
      // If no url was configured, fall back to a hardcoded route.
      $url_object = Url::fromRoute($logged_in ? 'user.page' : '<front>');
    }

    return $url_object;
  }

  /**
   * Converts a URL to a response object that is suitable for this controller.
   *
   * @param string|\Drupal\Core\Url $url
   *   A URL to redirect to, either as a string or a Drupal URL object. (Drupal
   *   code usually creates and passes objects, but the SAML toolkit methods
   *   return strings, so we allow those to be passed without conversion.)
   * @param bool $cacheable_and_can_be_external
   *   If TRUE, $url is allowed to be external. (By default, external URLs
   *   cause an exception to be thrown later on, saying they are disallowed.)
   *   It's also cacheable. The downside to this is, code doing this MUST NOT
   *   call any 'unknown' code (meaning: any calls to code that might call
   *   hooks / fire events is disallowed), because that would open us up to the
   *   dreaded 'leaked metadata' exception. We're overloading this parameter to
   *   have two uses for as long as we can get away with it, because 1) it's a
   *   protected 'internal' method, not bound to any interface; 2) we want as
   *   few different return values as possible; it's been confusing enough
   *   getting our code to this point where we can prevent any exceptions.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse|\Drupal\Core\Routing\TrustedRedirectResponse
   *   A response object representing a redirect: a Symfony RedirectResponse by
   *   default; TrustedRedirectResponse (which is cacheable and can be
   *   external) if $cacheable_and_can_be_external is TRUE.
   */
  protected function createRedirectResponse($url, $cacheable_and_can_be_external = FALSE) {
    if (is_object($url)) {
      // This construct is needed to prevent exceptions; see comments at
      // getUrlFromDestination(). The difference: in some cases we'll actually
      // add the metadata into the response (because we can, and because we're
      // returning a response object rather than a string).
      $generated_url_object = $url->toString(TRUE);
      $url = $generated_url_object->getGeneratedUrl();
    }
    if ($cacheable_and_can_be_external) {
      // We have to use TrustedRedirectResponse here; just a RedirectResponse
      // is prohibited from handling an external URL.
      $response = new TrustedRedirectResponse($url);
      if (isset($generated_url_object)) {
        // We shouldn't have to add cacheability metadata to our response
        // object when the route is configured to not cache responses in our
        // routing.yml. Do it anyway to prevent future obscure bugs with new
        // routes.
        $response->addCacheableDependency($generated_url_object);
      }
    }
    else {
      // NOTE: all the above fussing over the use of toString() / handling of
      // cacheability metadata is about getting our own code to do the right
      // thing. However we can't prevent 'external' code (called on user login/
      // insert/update hooks or the events fired by SamlService) from doing the
      // wrong thing, so we have to take measures to prevent that external code
      // from causing the 'leaked metadata' exception when we issue a
      // redirect. There are several things we could do:
      // - Patch Drupal to not throw exceptions if our response isn't cacheable
      //   in the first place, as specified by our routing.yml ;-)
      // - Create our own render context which 'catches' the cacheability
      //   metadata that e.g. external toString() calls could have generated
      //   in the background, so that the current render context (created by
      //   our callers) does not see that metadata and throw an exception. This
      //   could be done by e.g. adding the following code around our acs():
      //   $RENDERER_SERVICE->executeInRenderContext(new RenderContext(), $this->acs());
      //   This construct immediately discards the metadata; we don't need it
      //   because our responses aren't cacheable anyway.
      // - Use a Symfony RedirectResponse. Since that is not a cacheable
      //   response, our callers won't check for unaccounted-for metadata and
      //   therefore can't throw the related exception.
      // We do the latter.
      $response = new RedirectResponse($url);
    }

    return $response;
  }

  /**
   * Displays and/or logs exception message.
   *
   * @param $exception
   *   The exception thrown.
   * @param string $while
   *   A description of when the error was encountered.
   */
  protected function handleException($exception, $while = '') {
    if ($exception instanceof UserVisibleException || $this->config->get('debug_display_error_details')) {
      // Show the full error on screen; also log, but with lowered severity.
      // Assume we don't need the "while" part for a user visible error because
      // it's likely not fully correct.
      \Drupal::messenger()->addError($exception->getMessage());
      $this->getLogger('samlauth')->warning($exception->getMessage());
    }
    else {
      // Use the same format for logging as Drupal's ExceptionLoggingSubscriber
      // except also specify where the error was encountered. (The options for
      // the "while" part are limited, so we make this part of the message
      // rather than a context parameter.)
      if ($while) {
        $while = " while $while";
      }
      $error = Error::decodeException($exception);
      unset($error['severity_level']);
      $this->getLogger('samlauth')->critical("%type encountered$while: @message in %function (line %line of %file).", $error);
      // Don't expose the error to prevent information leakage; the user probably
      // can't do much with it anyway. But hint that more details are available.
      \Drupal::messenger()->addError("Error encountered{$while}; details have been logged.");
    }
  }

}
