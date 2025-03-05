=== WP LoginShield ===
Contributors: budhilaw
Tags: security, login, custom login, admin, brute force, login security, login protection, login tracking, security monitoring, wp-admin, authentication
Requires at least: 5.0
Tested up to: 6.4
Stable tag: 1.0.1
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Enhance your WordPress site security by customizing the login URL path, protecting against brute force attacks, and tracking login attempts.

== Description ==

WP LoginShield allows you to change the default WordPress login URL (wp-login.php) to any custom path you prefer. This adds a layer of security to your WordPress site by making it harder for bots and potential attackers to find your login page.

= Features =

* Change the login URL to any custom path
* Block direct access to wp-login.php
* Optional IP banning after 3 failed login attempts
* Manage banned IP addresses
* Track all login attempts (successful and failed)
* Monitor all login page access attempts
* IP whitelist protection for login page access
* Custom timezone settings for log displays
* 12/24 hour time format options
* Export login and access records as CSV
* Easy to configure through the Settings page
* Live preview of your custom login URL
* Works with all permalink structures

= Security Benefits =

* Prevents brute force attacks targeting the default login URL
* Reduces automated bot traffic to your login page
* Makes it more difficult for attackers to find your login page
* Automatically bans IP addresses with multiple failed login attempts (optional)
* Temporary ban period prevents continual login attempts
* Provides complete visibility of all login activity with IP tracking
* Detailed access monitoring shows who is trying to access your login page
* Advanced analytics on login page access attempts with referrer tracking

= How to Use =

1. Install and activate the plugin
2. Go to Settings > WP LoginShield
3. Enter your desired login path
4. Optionally enable IP banning for additional security
5. Optionally enable login tracking to monitor all login attempts
6. Optionally enable IP whitelist to restrict access to trusted IPs
7. Optionally enable Access Monitoring to track all login page access attempts
8. Save Changes
9. Your new login URL will be: yourdomain.com/your-custom-path

= Who Made This Plugin? =

WP LoginShield was developed by [Budhilaw](https://budhilaw.com), a WordPress security specialist with years of experience in developing custom security solutions for WordPress websites. 

Need a custom WordPress solution for your business? Feel free to [contact me](https://budhilaw.com/contact) for:

* Custom WordPress theme development
* Custom plugin development
* WordPress security hardening
* Website migration and optimization
* E-commerce solutions
* Performance optimization

Visit [my website](https://budhilaw.com) to see my portfolio and other WordPress services.

== Installation ==

1. Upload the `wp-login-shield` folder to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Go to Settings > WP LoginShield to configure your custom login URL

== Frequently Asked Questions ==

= What happens if I forget my custom login URL? =

If you forget your custom login URL, you can access your WordPress admin in two ways:

1. Check the WP LoginShield settings in your database in the `wp_options` table
2. Use FTP to deactivate the plugin by renaming its folder

= What does the IP ban feature do? =

When enabled, the IP ban feature will temporarily ban any IP address that has 3 or more failed login attempts within a 24-hour period. This helps protect your site against brute force attacks where attackers try multiple username and password combinations.

= How long does an IP ban last? =

By default, an IP ban lasts for 24 hours from the time of the last failed login attempt.

= What does the login tracking feature do? =

When enabled, the login tracking feature records all login attempts to your WordPress site, both successful and failed. It captures the IP address, username, timestamp, and user agent (browser/device) information for each attempt. This helps you monitor who is trying to access your site and identify potential security threats.

= What is Access Monitoring and how is it different from Login Tracking? =

While Login Tracking records actual login attempts (when someone submits the login form), Access Monitoring tracks every attempt to even view the login page. This gives you visibility into reconnaissance activities and potential attackers before they even try to log in. It captures IP address, timestamp, referrer URL, and whether the IP is whitelisted.

= How many login attempts are saved? =

The plugin stores up to 500 most recent login attempts to prevent your database from becoming too large.

= Can I export the login tracking data? =

Yes, you can export all login tracking data as a CSV file that you can open in spreadsheet applications like Excel or Google Sheets for further analysis.

= Can I manually unban an IP address? =

Yes, if you have enabled the IP ban feature, you can manage all banned IP addresses by going to Settings > WP LoginShield > Banned IPs tab. From there, you can unban individual IP addresses or clear all bans.

= Will this affect other plugins that use the login page? =

No, this plugin preserves all WordPress login functionality. It simply changes the URL path while maintaining all standard login features.

= Is this compatible with WordPress Multisite? =

Yes, the plugin works with WordPress Multisite installations.

== Screenshots ==

1. The WP LoginShield settings page
2. Example of custom login URL in action
3. Banned IP addresses management page
4. Login tracking and monitoring page
5. Access monitoring dashboard view

== Changelog ==

= 1.0.1 =
* Enhanced UI for access monitoring page
* Fixed date formatting issues in banned IPs and login tracking
* Improved About page with professional layout
* Added additional details to login tracking display
* Fixed various bugs and improved stability
* Updated documentation and branding

= 1.0.0 =
* Initial release with custom login path feature
* Added IP banning functionality after failed login attempts
* Added login attempt tracking and monitoring

== Upgrade Notice ==

= 1.0.1 =
This update improves the user interface, fixes date formatting issues, and enhances the Access Monitoring feature.

= 1.0.0 =
Initial release 