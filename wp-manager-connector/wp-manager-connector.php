<?php
/**
 * Plugin Name:       WP Manager Connector
 * Plugin URI:        https://yourwebsite.com
 * Description:       Companion plugin for the Perfex CRM WordPress Manager module.
 * Version:           1.1.2
 * Author:            Erick Castillo
 * Author URI:        https://www.erick-castillo.com
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       wp-manager-connector
 * Domain Path:       /languages
 */

if ( ! defined( 'WPINC' ) ) {
    die;
}

define( 'WPM_CONNECTOR_VERSION', '1.1.1' );
define( 'WPM_CONNECTOR_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );

require WPM_CONNECTOR_PLUGIN_DIR . 'includes/class-wp-manager-connector.php';

function run_wp_manager_connector() {
    $plugin = new WP_Manager_Connector();
    $plugin->run();
}
run_wp_manager_connector();
