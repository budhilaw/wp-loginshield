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
        
        // Initialize sortable
        if ($('.wp-login-shield-sortable').length) {
            $('.wp-login-shield-sortable').sortable({
                handle: '.wp-login-shield-card-header',
                placeholder: 'wp-login-shield-sortable-placeholder',
                opacity: 0.7
            });
        }
        
        // Toggle card body
        $('.handlediv').on('click', function() {
            var $this = $(this);
            var $body = $this.closest('.wp-login-shield-card').find('.wp-login-shield-card-body');
            var isExpanded = $this.attr('aria-expanded') === 'true';
            
            $body.toggleClass('closed');
            $this.attr('aria-expanded', !isExpanded);
            
            // Update toggle indicator
            $this.find('.toggle-indicator').css('transform', isExpanded ? 'rotate(180deg)' : 'rotate(0deg)');
        });
        
        // Initialize the toggle indicators on page load
        $('.handlediv').each(function() {
            var $this = $(this);
            var isExpanded = $this.attr('aria-expanded') === 'true';
            
            // Set initial rotation
            $this.find('.toggle-indicator').css('transform', isExpanded ? 'rotate(0deg)' : 'rotate(180deg)');
            
            // Set initial body state
            if (!isExpanded) {
                $this.closest('.wp-login-shield-card').find('.wp-login-shield-card-body').addClass('closed');
            }
        });
    });

})(jQuery); 