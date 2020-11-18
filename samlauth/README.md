INTRODUCTION
------------
This module allows users to authenticate against a SAML Identity Provider (IdP)
to log in to a Drupal application.

Essential basics of SAML, tuned to our situation: The IdP is the remote system
which users are directed to upon login, which authorizes the user to log into
our site. The Service Provider (SP) is a standalone piece of code (implemented
by the SAML PHP Toolkit) which takes care of the SAML communication /
validating the assertions sent back by the IdP.

In our case, the SP is integrated into the Drupal site: the SAML Authentication
module
- enables configuring most options for the SP
- exposes some URL paths which pass HTTP requests (which either start the login
  procedure or are redirected back from the IdP) into the SP library/code
- logs the user in to Drupal / out of Drupal, after the SP has validated the
  assertions in these HTTP requests.

For more information about SAML, see: https://en.wikipedia.org/wiki/SAML_2.0

A detailed explanation on how to use this module (v1) is available at:
https://www.youtube.com/watch?v=7XCp0SvFoPQ - although it's aging.

INSTALLATION
------------
Install as you would normally install a contributed drupal module. See:
https://www.drupal.org/documentation/install/modules-themes/modules-8
for further information.

REQUIREMENTS
------------
This module depends on OneLogin's SAML PHP Toolkit:
https://github.com/onelogin/php-saml. This is automatically installed if you
installed the module using Composer.

During configuration,

- We need an SSL public/private key pair. Without going into detail: the most
  common way of creating keys is the following openssl command:
  ```
  openssl req -new -x509 -days 3652 -nodes -out sp.crt -keyout sp.key
  ```
- We need to exchange information with the IdP, because both parties need to
  configure the other's identity/location. More details are in the respective
  configuration sections.

CONFIGURATION AND TESTING
-------------------------
Testing SAML login is often a challenge to get right in one go. For those not
familiar with SAML setup, it may be less confusing to test things in separate
steps, so several configuration sections below document a specific action to
take after configuring that one section. You're free to either take those
actions or configure all options first.

Go to /admin/config/people/saml to configure the module.

### Login / Logout:

Hopefully this speaks for itself. This can be skipped for now, unless you want
a menu item to be visible for testing login. The URL path to start the login
process is /saml/login.

### Service Provider:

Unless you want to store the keys in the database: create a folder in a
'private' location (accessible by Drupal but not accessible over the web),
named "certs". Place the files sp.key and sp.crt inside them. (These specific
folder / file names are mandatory.) Configure the folder name in the
"Certificate Folder" element.

The Entity ID can be any value, used to identify this particular SP / Drupal
application to the IdP - as long as it is unique among all SPs known by the
IdP. (Many SPs make it equal to the URL for the application or metadata, but
that's just a convention. Choose anything you like - unless the organisation
operating the IdP is already mandating a specific value.)

After saving this configuration, the metadata URL should contain all
information (as an XML file) necessary for the IdP to configure our information
on their side. If you're curious and/or know details about what the IdP
expects, you can go through the "SAML Message Construction" / "SAML Response
Validation" sections first, to get details of the XML exactly right, but those
details are very likely unneeded. When in doubt, this is the point at which you
can provide information to the IdP:

- save the XML file from the metadata URL (/saml/metadata) and hand it to (the
  person administering) the IdP
- or: go to admin/people/permissions#module-samlauth to enable permission to
  view the metadata, and give the URL to the IdP
- or: just give them the Entity ID and public certificate (the file sp.crt)

### Identity Provider:

The information in this section must be provided by the IdP. Likely they
provide it in a metadata file in XML format (at a URL which may or may not be
publicly accessible).

Copy the information from the XML file into this section.

At this point, the communication between IdP and SP can be tested, though users
will not be logged into Drupal yet. If a login attempt is terminated with an
error "Configured unique ID is not present in SAML response", the configuration
is correct and you can continue with the "User info" section.

In other cases, something is going wrong in the SAML communication. If the
error is not obvious, read through the "SAML Message Construction" / "SAML
Response Validation" sections to see if there are corresponding settings to
adjust. (For instance, if some validation of signatures fails, try to turn
strictness/validation settings off. But please fix validation issues and turn
them back on later, for improved security.)

### USER INFO AND SYNCING

The most important configuration value to get right from the start, is the
"Unique ID attribute". Each user logging in through SAML needs to be identified
with a unique value that never changes over time. This value is stored by
Drupal in the authmap table. (If you make a mistake configuring things here,
all samlauth entries should be removed from the authmap table after fixing the
configuration.)

This value must get sent from the IdP as an 'attribute' in the SAML response,
along with other attributes containing information like the user name and
e-mail. (SAML also has the concept of "NameID" to use for this unique value
instead of attributes, but this Drupal module does not support that yet.)

To configure the Unique ID and other attributes, you need to know the names of
the attributes which the IdP sends in its login assertions. If you do not know
this information, you need to inspect the contents of such an assertion while a
user tries to log in. See the section on Debugging.

If there is absolutely no unique non-changing value to set as Unique ID, you
can take the username or e-mail attribute - but please note that a new Drupal
user will be created every time that username/e-mail is changed on the IdP
side.

Other settings / checkboxes are hopefully self-explanatory.

### SAML Message Construction / SAML Response Validation

This ever expanding section of advanced configuration won't be discussed here
in detail; hopefully the setting descriptions give a clue. Just some hints:

- Turn strictness / signing / validation settings off only for testing / if
  absolutely needed.
- The "NameID" related settings can likely be turned off, as long as the Drupal
  module has no support for NameID / if the IdP is using a SAML attribute to
  supply the Unique ID value. (I didn't want to turn them off by default
  until some further module work was done, though.)

DEBUGGING
---------

Besides the debugging options available in the configuration screen, you can 
use third party tools to help debug your SSO flow with SAML. The following are
browser extensions that can be used on Linux, macOS and Windows:

Google Chrome:
- SAML Chrome Panel: https://chrome.google.com/webstore/detail/saml-chrome-panel/paijfdbeoenhembfhkhllainmocckace

FireFox:
- SAML Tracer: https://addons.mozilla.org/en-US/firefox/addon/saml-tracer/

These tools will allow you to see the SAML request/response and the method
(GET, POST or Artifact) the serialized document is sent/received.

If you are configuring a new SAML connection it is wise to first test without
encryption enabled and then enable encryption once a non encrypted assertion
is successful.

The listed third party tools do not decrypt SAML assertions, but you can use
OneLogin's Decrypt XML tool at https://www.samltool.com/decrypt.php.

You can also find more debugging tools located at
https://www.samltool.com/saml_tools.php.
