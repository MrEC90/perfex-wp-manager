<?php

class WP_Manager_REST_Controller {

    protected $plugin_name;
    protected $version;
    protected $namespace;

    public function __construct($plugin_name, $version) {
        $this->plugin_name = $plugin_name;
        $this->version = $version;
        $this->namespace = 'wpmanager/v1';
    }

    public function register_routes() {
        register_rest_route($this->namespace, '/ping', ['methods' => 'GET', 'callback' => [$this, 'ping_connection'], 'permission_callback' => [$this, 'permissions_check']]);
        register_rest_route($this->namespace, '/updates', ['methods' => 'GET', 'callback' => [$this, 'get_update_data'], 'permission_callback' => [$this, 'permissions_check']]);
        register_rest_route($this->namespace, '/themes', ['methods' => 'GET', 'callback' => [$this, 'get_themes_data'], 'permission_callback' => [$this, 'permissions_check']]);
        register_rest_route($this->namespace, '/plugins', ['methods' => 'GET', 'callback' => [$this, 'get_plugins_data'], 'permission_callback' => [$this, 'permissions_check']]);
        register_rest_route($this->namespace, '/users', ['methods' => 'GET', 'callback' => [$this, 'get_users_data'], 'permission_callback' => [$this, 'permissions_check']]);
        
        register_rest_route($this->namespace, '/update/all', ['methods' => 'POST', 'callback' => [$this, 'do_all_updates'], 'permission_callback' => [$this, 'permissions_check']]);
        register_rest_route($this->namespace, '/update/core', ['methods' => 'POST', 'callback' => [$this, 'do_core_update'], 'permission_callback' => [$this, 'permissions_check']]);
        register_rest_route($this->namespace, '/update/plugins', ['methods' => 'POST', 'callback' => [$this, 'do_plugin_updates'], 'permission_callback' => [$this, 'permissions_check']]);
        register_rest_route($this->namespace, '/update/themes', ['methods' => 'POST', 'callback' => [$this, 'do_theme_updates'], 'permission_callback' => [$this, 'permissions_check']]);

        register_rest_route($this->namespace, '/themes/activate', ['methods' => 'POST', 'callback' => [$this, 'activate_theme'], 'permission_callback' => [$this, 'permissions_check']]);
        register_rest_route($this->namespace, '/themes/delete', ['methods' => 'POST', 'callback' => [$this, 'delete_theme'], 'permission_callback' => [$this, 'permissions_check']]);
        register_rest_route($this->namespace, '/themes/upload', ['methods' => 'POST', 'callback' => [$this, 'upload_theme'], 'permission_callback' => [$this, 'permissions_check']]);

        register_rest_route($this->namespace, '/plugins/action', ['methods' => 'POST', 'callback' => [$this, 'manage_plugin'], 'permission_callback' => [$this, 'permissions_check']]);
        register_rest_route($this->namespace, '/plugins/upload', ['methods' => 'POST', 'callback' => [$this, 'upload_plugin'], 'permission_callback' => [$this, 'permissions_check']]);

        register_rest_route($this->namespace, '/users/manage', ['methods' => 'POST', 'callback' => [$this, 'manage_user'], 'permission_callback' => [$this, 'permissions_check']]);
    }

    public function get_users_data(WP_REST_Request $request) {
        $users = get_users();
        $response_data = [];
        foreach ($users as $user) {
            $response_data[] = [
                'ID' => $user->ID,
                'user_login' => $user->user_login,
                'user_email' => $user->user_email,
                'role' => !empty($user->roles) ? ucfirst($user->roles[0]) : 'N/A',
                'first_name' => $user->first_name,
                'last_name' => $user->last_name,
                'user_url' => $user->user_url,
                'description' => $user->description,
            ];
        }
        return new WP_REST_Response($response_data, 200);
    }

    public function manage_user(WP_REST_Request $request) {
        $action = $request->get_param('user_action');
        $user_id = $request->get_param('user_id');
        $user_data = $request->get_param('user_data');

        if (empty($action)) {
            return new WP_Error('missing_action', 'User action not specified.', ['status' => 400]);
        }

        switch ($action) {
            case 'create':
                if (empty($user_data['user_login']) || empty($user_data['user_pass']) || empty($user_data['user_email'])) {
                    return new WP_Error('missing_create_params', 'Username, password, and email are required to create a user.', ['status' => 400]);
                }
                
                $new_user_id = wp_insert_user($user_data);

                if (is_wp_error($new_user_id)) {
                    return new WP_Error('user_create_failed', $new_user_id->get_error_message(), ['status' => 500]);
                }

                if (isset($user_data['send_user_notification']) && $user_data['send_user_notification'] === 'true') {
                    wp_send_new_user_notifications($new_user_id);
                }

                return new WP_REST_Response(['status' => 'success', 'message' => 'User created successfully.'], 200);

            case 'update':
                if (empty($user_id)) {
                    return new WP_Error('missing_update_params', 'User ID is required for updates.', ['status' => 400]);
                }
                
                $user_data['ID'] = $user_id;
                $updated_user_id = wp_update_user($user_data);

                if (is_wp_error($updated_user_id)) {
                     return new WP_Error('user_update_failed', $updated_user_id->get_error_message(), ['status' => 500]);
                }

                $messages = ['User details updated.'];

                if (!empty($user_data['user_pass'])) {
                    $messages[] = 'Password updated.';
                }

                if (!empty($user_data['role'])) {
                    $user = new WP_User($user_id);
                    $user->set_role($user_data['role']);
                    $messages[] = 'Role updated.';
                }

                return new WP_REST_Response(['status' => 'success', 'message' => implode(' ', $messages)], 200);

            case 'delete':
                if (empty($user_id)) {
                    return new WP_Error('missing_delete_params', 'User ID is required.', ['status' => 400]);
                }
                require_once ABSPATH . 'wp-admin/includes/user.php';
                wp_delete_user($user_id);
                return new WP_REST_Response(['status' => 'success', 'message' => 'User deleted successfully.'], 200);
            
            default:
                return new WP_Error('invalid_action', "The specified user action '{$action}' is not valid.", ['status' => 400]);
        }
    }

    public function permissions_check(WP_REST_Request $request) { $token = $request->get_param('token'); $expected_token = get_option('wp_manager_connector_token', 'changeme123'); if (empty($token) || !hash_equals($expected_token, $token)) { return new WP_Error('rest_forbidden', 'Invalid token.', ['status' => 403]); } return true; }
    public function ping_connection(WP_REST_Request $request) { return new WP_REST_Response(['status' => 'success', 'message' => 'Connection successful.'], 200); }
    public function get_themes_data(WP_REST_Request $request) { wp_update_themes(); $all_themes = wp_get_themes(); $update_themes = get_site_transient('update_themes'); $active_theme = wp_get_theme(); $response_data = []; foreach ($all_themes as $stylesheet => $theme) { $is_child = $theme->parent() ? true : false; $response_data[$stylesheet] = [ 'name' => $theme->get('Name'), 'version' => $theme->get('Version'), 'author' => $theme->get('Author'), 'is_active' => ($stylesheet === $active_theme->get_stylesheet()), 'is_child_theme' => $is_child, 'is_parent_theme' => !$is_child, 'has_update' => isset($update_themes->response[$stylesheet]), 'new_version' => isset($update_themes->response[$stylesheet]) ? $update_themes->response[$stylesheet]['new_version'] : null, ]; } return new WP_REST_Response($response_data, 200); }
    public function get_plugins_data(WP_REST_Request $request) { if (!function_exists('get_plugins')) { require_once ABSPATH . 'wp-admin/includes/plugin.php'; } wp_update_plugins(); $all_plugins = get_plugins(); $update_plugins = get_site_transient('update_plugins'); $response_data = []; foreach ($all_plugins as $plugin_path => $plugin) { $response_data[$plugin_path] = [ 'name' => $plugin['Name'], 'version' => $plugin['Version'], 'author' => $plugin['Author'], 'is_active' => is_plugin_active($plugin_path), 'has_update' => isset($update_plugins->response[$plugin_path]), 'new_version' => isset($update_plugins->response[$plugin_path]) ? $update_plugins->response[$plugin_path]->new_version : null, ]; } return new WP_REST_Response($response_data, 200); }
    public function manage_plugin(WP_REST_Request $request) { if (!function_exists('get_plugins')) { require_once ABSPATH . 'wp-admin/includes/plugin.php'; } $plugin_path = $request->get_param('plugin_path'); $action = $request->get_param('plugin_action'); if (empty($plugin_path) || empty($action)) { return new WP_Error('missing_params', 'Missing required parameters.', ['status' => 400]); } $result = null; switch ($action) { case 'activate': $result = activate_plugin($plugin_path); break; case 'deactivate': $result = deactivate_plugins($plugin_path); break; case 'delete': $result = delete_plugins([$plugin_path]); break; } if (is_wp_error($result)) { return new WP_Error('action_failed', $result->get_error_message(), ['status' => 500]); } return new WP_REST_Response(['status' => 'success', 'message' => 'Plugin action (' . $action . ') completed successfully.'], 200); }
    
    public function upload_plugin(WP_REST_Request $request) {
        if (empty($_FILES['plugin_zip'])) {
            return new WP_Error('no_file', 'No plugin file was uploaded.', ['status' => 400]);
        }
    
        $this->include_upgrader();
    
        $skin = new Automatic_Upgrader_Skin();
        $upgrader = new Plugin_Upgrader($skin);
    
        $result = $upgrader->install($_FILES['plugin_zip']['tmp_name'], ['overwrite_package' => true]);
    
        if (is_wp_error($result)) {
            $error_message = $result->get_error_message();
            return new WP_Error('install_failed', $error_message, ['status' => 500]);
        }
    
        if ($result === false) {
            return new WP_Error('install_failed', 'An unknown error occurred during installation.', ['status' => 500]);
        }
    
        $activate = $request->get_param('activate') === 'true';
        if ($activate) {
            $plugin_path = $upgrader->plugin_info();
            if ($plugin_path) {
                activate_plugin($plugin_path);
            }
        }
    
        return new WP_REST_Response(['status' => 'success', 'message' => 'Plugin installed/updated successfully.'], 200);
    }

    public function upload_theme(WP_REST_Request $request) { if (empty($_FILES['theme_zip'])) { return new WP_Error('no_file', 'No theme file was uploaded.', ['status' => 400]); } $this->include_upgrader(); $skin = new Automatic_Upgrader_Skin(); $upgrader = new Theme_Upgrader($skin); $result = $upgrader->install($_FILES['theme_zip']['tmp_name'], ['overwrite_package' => false]); if (is_wp_error($result) || !$result) { $error_message = is_wp_error($result) ? $result->get_error_message() : 'An unknown error occurred during installation.'; return new WP_Error('install_failed', $error_message, ['status' => 500]); } $activate = $request->get_param('activate') === 'true'; if ($activate) { $stylesheet = $upgrader->theme_info()->get_stylesheet(); if ($stylesheet) { switch_theme($stylesheet); } } return new WP_REST_Response(['status' => 'success', 'message' => 'Theme installed successfully.'], 200); }
    public function activate_theme(WP_REST_Request $request) { $stylesheet = $request->get_param('stylesheet'); if (empty($stylesheet)) { return new WP_Error('no_stylesheet', 'No theme stylesheet provided.', ['status' => 400]); } $theme = wp_get_theme($stylesheet); if (!$theme->exists() || !$theme->is_allowed()) { return new WP_Error('theme_not_found', 'The specified theme is not valid.', ['status' => 404]); } switch_theme($stylesheet); if (get_stylesheet() === $stylesheet) { return new WP_REST_Response(['status' => 'success', 'message' => 'Theme activated successfully.'], 200); } else { return new WP_Error('activation_failed', 'Could not activate the theme.', ['status' => 500]); } }
    public function delete_theme(WP_REST_Request $request) { $stylesheet = $request->get_param('stylesheet'); if (empty($stylesheet)) { return new WP_Error('no_stylesheet', 'No theme stylesheet provided.', ['status' => 400]); } require_once ABSPATH . 'wp-admin/includes/theme.php'; $result = delete_theme($stylesheet); if (is_wp_error($result)) { return new WP_Error('delete_failed', $result->get_error_message(), ['status' => 500]); } return new WP_REST_Response(['status' => 'success', 'message' => 'Theme deleted successfully.'], 200); }
    public function get_update_data(WP_REST_Request $request) { wp_version_check(); wp_update_plugins(); wp_update_themes(); $updates = get_site_transient('update_core'); $plugin_updates = get_site_transient('update_plugins'); $theme_updates = get_site_transient('update_themes'); $response_data = ['core' => [], 'plugins' => [], 'themes' => [], 'counts' => ['core' => 0, 'plugins' => 0, 'themes' => 0, 'total' => 0]]; if (isset($updates->updates) && !empty($updates->updates) && $updates->updates[0]->response !== 'latest') { $response_data['core'][] = ['name' => 'WordPress Core', 'current_version' => get_bloginfo('version'), 'new_version' => $updates->updates[0]->version]; $response_data['counts']['core'] = count($response_data['core']); } if (isset($plugin_updates->response) && !empty($plugin_updates->response)) { foreach ($plugin_updates->response as $plugin_file => $update_data) { $plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin_file); $response_data['plugins'][] = ['name' => $plugin_data['Name'], 'current_version' => $plugin_data['Version'], 'new_version' => $update_data->new_version]; } $response_data['counts']['plugins'] = count($response_data['plugins']); } if (isset($theme_updates->response) && !empty($theme_updates->response)) { foreach ($theme_updates->response as $theme_stylesheet => $update_data) { $theme = wp_get_theme($theme_stylesheet); $response_data['themes'][] = ['name' => $theme->get('Name'), 'current_version' => $theme->get('Version'), 'new_version' => $update_data['new_version']]; } $response_data['counts']['themes'] = count($response_data['themes']); } $response_data['counts']['total'] = $response_data['counts']['core'] + $response_data['counts']['plugins'] + $response_data['counts']['themes']; return new WP_REST_Response($response_data, 200); }
    private function include_upgrader() { if (!function_exists('get_core_updates')) { require_once ABSPATH . 'wp-admin/includes/update.php'; } if (!class_exists('WP_Upgrader')) { require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php'; } if (!class_exists('Automatic_Upgrader_Skin')) { require_once ABSPATH . 'wp-admin/includes/class-automatic-upgrader-skin.php';} }
    public function do_all_updates(WP_REST_Request $request) { $this->do_core_update($request); $this->do_plugin_updates($request); $this->do_theme_updates($request); return new WP_REST_Response(['status' => 'success', 'message' => 'All update processes completed.'], 200); }
    public function do_core_update(WP_REST_Request $request) { $this->include_upgrader(); wp_version_check(); $core_updates = get_core_updates(); if (empty($core_updates) || !isset($core_updates[0]) || $core_updates[0]->response === 'latest') { return new WP_REST_Response(['status' => 'success', 'message' => 'WordPress core is already up to date.'], 200); } $upgrader = new Core_Upgrader(new Automatic_Upgrader_Skin()); $result = $upgrader->upgrade($core_updates[0]); if (is_wp_error($result)) { return new WP_Error('core_update_failed', $result->get_error_message(), ['status' => 500]); } return new WP_REST_Response(['status' => 'success', 'message' => 'WordPress core updated successfully.'], 200); }
    public function do_plugin_updates(WP_REST_Request $request) { $this->include_upgrader(); wp_update_plugins(); $plugin_updates = get_site_transient('update_plugins'); if (empty($plugin_updates->response)) { return new WP_REST_Response(['status' => 'success', 'message' => 'All plugins are up to date.'], 200); } $upgrader = new Plugin_Upgrader(new Automatic_Upgrader_Skin()); $plugins = array_keys($plugin_updates->response); $result = $upgrader->bulk_upgrade($plugins); if (is_wp_error($result)) { return new WP_Error('plugin_update_failed', 'An error occurred during plugin updates.', ['status' => 500, 'details' => $result]); } return new WP_REST_Response(['status' => 'success', 'message' => 'Plugins updated successfully.'], 200); }
    public function do_theme_updates(WP_REST_Request $request) { $this->include_upgrader(); wp_update_themes(); $theme_updates = get_site_transient('update_themes'); if (empty($theme_updates->response)) { return new WP_REST_Response(['status' => 'success', 'message' => 'All themes are up to date.'], 200); } $upgrader = new Theme_Upgrader(new Automatic_Upgrader_Skin()); $themes = array_keys($theme_updates->response); $result = $upgrader->bulk_upgrade($themes); if (is_wp_error($result)) { return new WP_Error('theme_update_failed', 'An error occurred during theme updates.', ['status' => 500, 'details' => $result]); } return new WP_REST_Response(['status' => 'success', 'message' => 'Themes updated successfully.'], 200); }
}
