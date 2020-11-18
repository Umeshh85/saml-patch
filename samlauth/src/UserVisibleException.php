<?php

namespace Drupal\samlauth;

use RuntimeException;

/**
 * A RuntimeException that contains messages that are safe to expose to users.
 */
class UserVisibleException extends RuntimeException {}
