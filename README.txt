=== WP Login Shield ===
Contributors: Ericsson Budhilaw
Tags: security, login, brute force, custom login, login monitoring, custom redirect
Requires at least: 5.0
Tested up to: 6.7
Stable tag: 1.0.4
Requires PHP: 7.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Enhance WordPress security by customizing the login path, blocking brute force attacks, and monitoring login attempts.

== Description ==

WP Login Shield provides comprehensive protection for your WordPress login page, safeguarding your site against unauthorized access attempts and brute force attacks.

= Key Features =

* **Custom Login Path**: Change your WordPress login URL to prevent automated attacks. Make your login page accessible via a custom path instead of the standard wp-login.php.
* **IP Banning**: Automatically ban IP addresses that attempt too many failed logins, protecting against brute force attacks.
* **Login Tracking**: Monitor all login attempts to your WordPress site with detailed information including timestamp, username, IP address, and user agent.
* **Access Monitoring**: Record all attempts to access your login page, even without login attempts, to detect reconnaissance activities.
* **IP Whitelisting**: Allow only specific IP addresses to access your login page for maximum security.
* **Custom Redirects**: Configure custom redirects for both unauthorized access attempts and after user logout.

= How It Works =

1. **Custom Login Protection**: When enabled, the standard wp-login.php page is protected and only accessible through your custom login path (e.g., /secret-login).
2. **Brute Force Prevention**: The plugin tracks failed login attempts and can automatically ban IPs that exceed the specified limit.
3. **Comprehensive Monitoring**: All login and access attempts are logged with detailed information for security analysis.
4. **Flexible Redirects**: Customize where users are sent after logout and where unauthorized users are redirected when attempting to access protected pages.

= Pro-level Security for Free =

WP Login Shield brings enterprise-level security features to all WordPress sites at no cost. By changing your login URL and monitoring access attempts, you can significantly reduce the risk of unauthorized access.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/wp-login-shield` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. Use the Settings -> WP Login Shield screen to configure the plugin.

== Frequently Asked Questions ==

= What happens if I forget my custom login path? =

You can always access your login page by directly using the URL with the token parameter: `wp-login.php?wls-token=your-custom-path`

= Will this plugin work with other security plugins? =

Yes, WP Login Shield is designed to complement other security plugins. It focuses specifically on login protection and can be used alongside other security measures.

= Can I disable certain features? =

Yes, each security feature (custom login path, IP banning, login tracking, custom redirects, etc.) can be enabled or disabled individually.

= What happens if I get locked out? =

If you're locked out, you can disable the plugin by renaming the plugin folder via FTP/SFTP or your hosting control panel.

= How can I clear banned IPs? =

You can manage banned IPs through the WP Login Shield -> Banned IPs page in your WordPress admin area.

== Screenshots ==

1. Main settings page
2. Custom login path configuration
3. Redirect settings configuration
4. Banned IPs management
5. Login tracking logs
6. Access monitoring page

== Changelog ==

= 1.0.4 =
* Added custom redirect option for after logout
* Added custom redirect option for unauthorized login attempts
* Improved user interface by hiding admin menu items for disabled features
* Admin menu now dynamically shows only enabled feature pages
* "Banned IPs" page only visible when IP banning is enabled
* "Login Tracking" page only visible when login tracking is enabled
* "Access Monitoring" page only visible when login access monitoring is enabled
* Enhanced error handling and security improvements

= 1.0.3 =
* Fixed minor security vulnerabilities
* Improved user agent detection
* Enhanced security with better error handling
* Code cleanup and performance optimizations

= 1.0.2 =
* Enhanced UI for all plugin screens
* Fixed pagination styling issues
* Improved login tracking display
* Bug fixes and performance improvements

= 1.0.1 =
* Fixed various bugs and improved stability
* Improved login URL handling for better plugin compatibility
* Enhanced security with 404 redirects

= 1.0.0 =
* Initial release

== Upgrade Notice ==

= 1.0.4 =
This update adds custom redirect options for both unauthorized access and after logout, along with various UI improvements and security enhancements.

= 1.0.2 =
This update improves the user interface, fixes pagination styling, and enhances overall plugin performance.

= 1.0.1 =
This update improves stability and fixes various minor bugs.

== Configuration ==

After installation, follow these steps to configure WP Login Shield:

1. **Custom Login Path**: Enable or disable this feature and set a custom path for your login page.
2. **Redirect Settings**:
   * Configure where unauthorized users are redirected when attempting to access protected pages
   * Set a custom redirect location for users after they log out
3. **IP Banning**: Enable automatic IP banning and set the maximum number of failed login attempts before banning.
4. **Login Tracking**: Enable tracking of all login attempts to monitor security events.
5. **IP Whitelisting**: Add trusted IP addresses that will always have access to the login page.
6. **Access Monitoring**: Enable monitoring of all login page access attempts.

For optimal security:
1. Use a unique, non-dictionary word for your custom login path
2. Enable IP banning with a reasonable threshold (3-5 attempts)
3. Regularly review login and access logs
4. Consider whitelisting your own IP address for guaranteed access
5. Set appropriate redirect paths for both blocked access and logout

== Privacy Policy ==

WP Login Shield collects and stores data to protect your WordPress site. Here's what you should know:

= Data Collected =

When enabled, WP Login Shield may collect and store:

* IP Addresses - Used to identify and ban repeated failed login attempts
* Usernames - For tracking login attempts (successful and failed)
* Timestamps - When login attempts and page accesses occur
* User Agent Strings - Browser/device information of visitors
* Referrer URLs - Where visitors came from before attempting access

= Data Usage =

This data is used solely for security purposes:
* Identifying and blocking malicious login attempts
* Monitoring for suspicious activity
* Creating security logs for administrator review
* Enforcing IP bans for brute force protection

= Data Storage =

* All collected data is stored in your WordPress database
* Login attempts are limited to 500 entries to prevent database bloat
* No data is transmitted to external servers

= Data Retention =

* Login and access records are stored until manually cleared by an administrator
* Banned IP records are stored until manually removed or until the ban expires

= Suggested Privacy Policy Content =

If you use this plugin, consider adding the following to your site's privacy policy:

"We use WP Login Shield to protect our login page from unauthorized access attempts. This plugin collects IP addresses, usernames, timestamps, and browser information when users attempt to access or log into our site. This information is stored in our database for security monitoring purposes and is not shared with third parties. IP addresses may be temporarily banned after multiple failed login attempts." 