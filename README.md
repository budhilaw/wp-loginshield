# WP Login Shield

> Enhance WordPress security by customizing the login path, blocking brute force attacks, and monitoring login attempts.

## Description

WP Login Shield provides comprehensive protection for your WordPress login page, safeguarding your site against unauthorized access attempts and brute force attacks.

![About WP Login Shield](assets/About.png)

### Key Features

- **Custom Login Path**: Change your WordPress login URL to prevent automated attacks
- **IP Banning**: Automatically ban IP addresses after too many failed login attempts
- **Login Tracking**: Monitor all login attempts with detailed information
- **Access Monitoring**: Record all attempts to access your login page
- **IP Whitelisting**: Allow only specific IP addresses to access your login page
- **Custom Redirects**: Configure custom redirects for both unauthorized access and after logout

## Installation

### From WordPress Dashboard

1. Navigate to **Plugins** → **Add New**
2. Search for "WP Login Shield"
3. Click **Install Now** and then **Activate**

### Manual Installation

1. Download the plugin zip file
2. Upload the plugin to your WordPress installation:
   - Unzip and upload the folder to `/wp-content/plugins/`
   - OR use the WordPress dashboard Upload Plugin feature
3. Activate the plugin through the 'Plugins' menu

## Configuration

After installation:

1. Navigate to **WP Login Shield** in your WordPress admin menu
2. Configure the following settings:

![Login Protection Settings](assets/Login-Protection-Settings.png)

### Custom Login Path

- Enable/disable the custom login path feature
- Set a custom path for your login page (e.g., "secret-login")
- Your login page will be accessible at: `yourdomain.com/secret-login`

### Redirect Settings

#### Blocked Access Redirect
- Enable/disable custom redirect for unauthorized login attempts
- Set a specific post or page slug to redirect unauthorized login attempts
- Your visitors will be redirected to this page instead of seeing a generic 404 page

#### Logout Redirect
- Enable/disable custom redirect after user logout
- Set a specific post or page slug where users will be redirected after logging out
- Perfect for directing users to a thank you page or back to your homepage

### IP Banning

- Enable automatic banning of IP addresses after failed login attempts
- Set the maximum number of failed attempts before banning

### Login Tracking

- Enable login attempt tracking
- View all login attempts with timestamp, username, IP, and user agent

### IP Whitelisting

- Add trusted IP addresses that will always have access
- Whitelist your own IP to prevent accidental lockouts

### Access Monitoring

- Record all attempts to access your login page
- Track reconnaissance activities before login attempts

## Security Recommendations

For optimal security:

1. Use a unique, non-dictionary word for your custom login path
2. Enable IP banning with a reasonable threshold (3-5 attempts)
3. Regularly review login and access logs
4. Consider whitelisting your own IP address for guaranteed access
5. Use strong passwords for all users
6. Set appropriate redirect paths for both blocked access and logout

## Usage

### Accessing Your Login Page

Once configured, your login page will be accessible at:
```
https://yourdomain.com/your-custom-path
```

If you forget your custom login path, you can always use:
```
https://yourdomain.com/wp-login.php?wls-token=your-custom-path
```

### Viewing Security Logs

1. Navigate to **WP Login Shield** → **Login Tracking** to view login attempts

![Login Tracking](assets/Login-Tracking.png)

2. Navigate to **WP Login Shield** → **Access Monitoring** to view login page access attempts

![Access Monitoring](assets/Access-Monitoring.png)

### Managing Banned IPs

Navigate to **WP Login Shield** → **Banned IPs** to:
- View all currently banned IP addresses
- Unban specific IP addresses
- Clear all bans

![Banned IPs](assets/Banned-IPs.png)

## FAQ

### What happens if I forget my custom login path?

You can access your login page by directly using the URL with the token parameter:
```
wp-login.php?wls-token=your-custom-path
```

### Will this plugin work with other security plugins?

Yes, WP Login Shield is designed to complement other security plugins. It focuses specifically on login protection and can be used alongside other security measures.

### Can I disable certain features?

Yes, each security feature (custom login path, IP banning, login tracking, etc.) can be enabled or disabled individually.

### What happens if I get locked out?

If you're locked out, you can disable the plugin by renaming the plugin folder via FTP/SFTP or your hosting control panel.

## Changelog

### 1.0.4
- Added custom redirect option for after logout
- Added custom redirect option for unauthorized login attempts
- Enhanced error handling for early protection
- Improved URL handling for WordPress installations in subdirectories
- Bug fixes and performance improvements

### 1.0.3
- Added custom redirect option for unauthorized login attempts
- Enhanced error handling for early protection
- Improved URL handling for WordPress installations in subdirectories
- Bug fixes and performance improvements

### 1.0.2
- Enhanced UI for all plugin screens
- Fixed pagination styling issues
- Improved login tracking display
- Bug fixes and performance improvements

### 1.0.1
- Fixed various bugs and improved stability
- Improved login URL handling for better plugin compatibility
- Enhanced security with 404 redirects

### 1.0.0
- Initial release

## Credits

- Developed by [Ericsson Budhilaw](https://github.com/budhilaw)

## License

WP Login Shield is licensed under the [GPL v2 or later](https://www.gnu.org/licenses/gpl-2.0.html).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request 