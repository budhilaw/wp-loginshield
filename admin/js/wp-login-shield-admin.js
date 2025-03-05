(function($) {
    'use strict';

    $(document).ready(function() {
        // Handle real-time preview of the login URL
        $('#wp_login_shield').on('input', function() {
            var value = $(this).val();
            
            // If empty, show the default
            if (value === '') {
                value = 'login'; // Default value
            }
            
            // Update the preview
            $('#preview-slug').text(value);
        });

        // Handle confirmation for unbanning IPs
        $('.unban-ip-button').on('click', function(e) {
            if (!confirm(wpLoginShieldAdmin.confirmUnban)) {
                e.preventDefault();
            }
        });

        // Handle confirmation for clearing all bans
        $('button[name="clear_all_bans"]').on('click', function(e) {
            if (!confirm(wpLoginShieldAdmin.confirmClearAll)) {
                e.preventDefault();
            }
        });
        
        // Handle confirmation for clearing all login records
        $('button[name="clear_all_login_attempts"]').on('click', function(e) {
            if (!confirm(wpLoginShieldAdmin.confirmClearAllAttempts)) {
                e.preventDefault();
            }
        });
    });

})(jQuery); 