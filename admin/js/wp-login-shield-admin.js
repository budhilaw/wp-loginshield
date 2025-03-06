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
        
        // SIMPLIFIED TOGGLE FUNCTIONALITY
        // Handle collapsible cards
        $('.wp-login-shield-card-header .handlediv').on('click', function() {
            var $button = $(this);
            var $card = $button.closest('.wp-login-shield-card');
            var $body = $card.find('.wp-login-shield-card-body');
            
            // Toggle visibility directly with jQuery
            $body.toggle();
            
            // Update aria-expanded attribute
            var isExpanded = $body.is(':visible');
            $button.attr('aria-expanded', isExpanded);
            
            // Store state in localStorage if available
            try {
                var key = 'wpls_card_' + $card.index();
                localStorage.setItem(key, isExpanded ? '1' : '0');
            } catch (e) {
                // Local storage might not be available
                console.log('LocalStorage not available');
            }
        });
        
        // Apply initial states on page load
        $('.wp-login-shield-card').each(function(index) {
            var $card = $(this);
            var $body = $card.find('.wp-login-shield-card-body');
            var $button = $card.find('.handlediv');
            
            try {
                var key = 'wpls_card_' + index;
                var savedState = localStorage.getItem(key);
                
                if (savedState === '0') {
                    $body.hide();
                    $button.attr('aria-expanded', 'false');
                }
            } catch (e) {
                // Local storage might not be available
                console.log('LocalStorage not available for reading');
            }
        });
    });

})(jQuery); 