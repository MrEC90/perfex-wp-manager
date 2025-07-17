<?php

class WP_Manager_Connector {

    protected $loader;
    protected $plugin_name;
    protected $version;

    public function __construct() {
        $this->plugin_name = 'wp-manager-connector';
        $this->version = WPM_CONNECTOR_VERSION;
        $this->load_dependencies();
    }

    private function load_dependencies() {
        require_once WPM_CONNECTOR_PLUGIN_DIR . 'includes/class-wp-manager-rest-controller.php';
        require_once WPM_CONNECTOR_PLUGIN_DIR . 'includes/class-wp-manager-admin.php';
    }

    public function run() {
        // Register REST API routes
        $rest_controller = new WP_Manager_REST_Controller($this->plugin_name, $this->version);
        add_action('rest_api_init', [$rest_controller, 'register_routes']);

        // Add admin menu
        $admin = new WP_Manager_Admin($this->plugin_name, $this->version);
        add_action('admin_menu', [$admin, 'add_admin_menu']);
    }
}
