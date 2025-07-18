<?php

class WP_Manager_Admin {

    private $plugin_name;
    private $version;

    public function __construct($plugin_name, $version) {
        $this->plugin_name = $plugin_name;
        $this->version = $version;

        // Generate a token on activation if it doesn't exist
        if (!get_option('wp_manager_connector_token')) {
            update_option('wp_manager_connector_token', wp_generate_password(32, false));
        }
    }

    public function add_admin_menu() {
        add_options_page(
            'WP Manager Connector',
            'WP Manager Connector',
            'manage_options',
            $this->plugin_name,
            [$this, 'display_admin_page']
        );
    }

    public function display_admin_page() {
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
            <p>This plugin connects your WordPress site to the Perfex CRM WordPress Manager module.</p>
            
            <div id="wpm-connector-settings-card" style="background: #fff; border: 1px solid #ccd0d4; padding: 1px 20px; max-width: 600px;">
                <h2>Connection Details</h2>
                <p>To connect your site, enter the following details in your Perfex CRM WordPress Manager settings:</p>
                
                <table class="form-table" role="presentation">
                    <tbody>
                        <tr>
                            <th scope="row"><label for="site_url">Site URL</label></th>
                            <td>
                                <input name="site_url" type="text" id="site_url" value="<?php echo esc_url(site_url()); ?>" readonly class="regular-text">
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="security_token">Security Token</label></th>
                            <td>
                                <input name="security_token" type="text" id="security_token" value="<?php echo esc_attr(get_option('wp_manager_connector_token')); ?>" readonly class="regular-text">
                                <p class="description">This token is required for the API connection.</p>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
        <?php
    }
}
