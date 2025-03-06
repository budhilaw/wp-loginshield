=== WP Login Shield ===
Contributors: budhilaw
Tags: security, login, brute force, protection, custom login, login monitoring
Requires at least: 5.0
Tested up to: 6.4
Stable tag: 1.0.2
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

= How It Works =

1. **Custom Login Protection**: When enabled, the standard wp-login.php page is protected and only accessible through your custom login path (e.g., /secret-login).
2. **Brute Force Prevention**: The plugin tracks failed login attempts and can automatically ban IPs that exceed the specified limit.
3. **Comprehensive Monitoring**: All login and access attempts are logged with detailed information for security analysis.

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

Yes, each security feature (custom login path, IP banning, login tracking, etc.) can be enabled or disabled individually.

= What happens if I get locked out? =

If you're locked out, you can disable the plugin by renaming the plugin folder via FTP/SFTP or your hosting control panel.

= How can I clear banned IPs? =

You can manage banned IPs through the WP Login Shield -> Banned IPs page in your WordPress admin area.

== Screenshots ==

1. Main settings page
2. Custom login path configuration
3. Banned IPs management
4. Login tracking logs
5. Access monitoring page

== Changelog ==

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

= 1.0.2 =
This update improves the user interface, fixes pagination styling, and enhances overall plugin performance.

= 1.0.1 =
This update improves stability and fixes various minor bugs.

== Configuration ==

After installation, follow these steps to configure WP Login Shield:

1. **Custom Login Path**: Enable or disable this feature and set a custom path for your login page.
2. **IP Banning**: Enable automatic IP banning and set the maximum number of failed login attempts before banning.
3. **Login Tracking**: Enable tracking of all login attempts to monitor security events.
4. **IP Whitelisting**: Add trusted IP addresses that will always have access to the login page.
5. **Access Monitoring**: Enable monitoring of all login page access attempts.

For optimal security:
1. Use a unique, non-dictionary word for your custom login path
2. Enable IP banning with a reasonable threshold (3-5 attempts)
3. Regularly review login and access logs
4. Consider whitelisting your own IP address for guaranteed access 