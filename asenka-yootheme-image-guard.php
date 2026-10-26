<?php
/**
 * Plugin Name: Asenka YOOtheme Image Guard
 * Plugin URI: https://github.com/Asenka-Dev-Team/Asenka-YOOtheme-Image-Guard
 * Description: Audits YOOtheme Pro image-handler exposure and reviews suspicious files, with quarantine and WP-CLI tools.
 * Version: 0.1.3
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Author: Asenka Interactive
 * Update URI: https://github.com/Asenka-Dev-Team/Asenka-YOOtheme-Image-Guard
 * License: GPL-2.0-or-later
 */
if (!defined('ABSPATH')) exit;
define('AYIG_VERSION','0.1.3');
define('AYIG_FILE',__FILE__);
define('AYIG_BASENAME',plugin_basename(__FILE__));
require_once __DIR__.'/includes/class-image-guard.php';
require_once __DIR__.'/includes/class-github-updater.php';
add_action('plugins_loaded',array('Asenka_YOOtheme_Image_Guard','init'));
add_action('init',array('Asenka_YOOtheme_Image_Guard_Updater','init'));
