<?php
if (!defined('ABSPATH')) exit;
final class Asenka_YOOtheme_Image_Guard_Updater {
 const OWNER='Asenka-Dev-Team'; const REPO='Asenka-Guard'; const CACHE='ayig_latest_release';
 static function init(){
  add_filter('update_plugins_github.com',[__CLASS__,'check'],10,4);
  add_filter('site_transient_update_plugins',[__CLASS__,'ensure_support'],20,1);
  add_filter('plugins_api',[__CLASS__,'info'],20,3);
  add_filter('upgrader_source_selection',[__CLASS__,'normalize'],10,4);
  add_action('admin_menu',[__CLASS__,'menu']);
  add_action('admin_post_ayig_refresh',[__CLASS__,'refresh']);
  add_filter('plugin_action_links_'.AYIG_BASENAME,[__CLASS__,'links']);
 }
 static function api($force=false){
  if(!$force){$cached=get_transient(self::CACHE);if(is_array($cached))return $cached;}
  $url='https://api.github.com/repos/'.self::OWNER.'/'.self::REPO.'/releases/latest';
  $response=wp_remote_get($url,['timeout'=>12,'headers'=>['Accept'=>'application/vnd.github+json','User-Agent'=>'Asenka-Guard/'.AYIG_VERSION]]);
  if(is_wp_error($response))return $response;
  if(wp_remote_retrieve_response_code($response)!==200)return new WP_Error('ayig_github','GitHub API returned HTTP '.wp_remote_retrieve_response_code($response));
  $data=json_decode(wp_remote_retrieve_body($response),true);
  if(!is_array($data)||empty($data['tag_name'])||empty($data['zipball_url'])||!empty($data['draft'])||!empty($data['prerelease']))return new WP_Error('ayig_release','No valid stable release found');
  $tag=$data['tag_name'];$version=ltrim($tag,'vV');
  if(!preg_match('/^\d+\.\d+\.\d+(?:\.[0-9]+)?$/',$version))return new WP_Error('ayig_tag','Unexpected release version tag');
  $expected='https://api.github.com/repos/'.self::OWNER.'/'.self::REPO.'/zipball/';
  if(strpos($data['zipball_url'],$expected)!==0)return new WP_Error('ayig_url','Unexpected release archive URL');
  $result=['version'=>$version,'tag'=>$tag,'zip'=>$data['zipball_url'],'notes'=>isset($data['body'])?wp_strip_all_tags($data['body']):'','url'=>'https://github.com/'.self::OWNER.'/'.self::REPO.'/releases/tag/'.rawurlencode($tag),'checked'=>time()];
  set_transient(self::CACHE,$result,HOUR_IN_SECONDS);return $result;
 }
 static function check($update,$plugin_data,$plugin_file,$locales){
  if($plugin_file!==AYIG_BASENAME)return $update;
  // Return stable-release metadata even when already up to date. WordPress
  // uses this response to populate update_plugins->no_update and enable its
  // native Automatic Updates column for a third-party plugin.
  $r=self::api();if(is_wp_error($r))return $update;
  return ['id'=>'https://github.com/'.self::OWNER.'/'.self::REPO,'slug'=>'asenka-yootheme-image-guard','plugin'=>AYIG_BASENAME,'version'=>$r['version'],'new_version'=>$r['version'],'url'=>$r['url'],'package'=>$r['zip'],'requires_php'=>'7.4'];
 }
 /**
  * Preserve native WordPress automatic-update controls even when GitHub is
  * unreachable or WordPress has not run its third-party update check yet.
  * Never fabricate a newer release, package URL, or update availability.
  */
 static function ensure_support($transient){
  if (!is_object($transient)) return $transient;
  if (!isset($transient->response) || !is_array($transient->response)) $transient->response=[];
  if (isset($transient->response[AYIG_BASENAME])) return $transient;
  if (!isset($transient->no_update) || !is_array($transient->no_update)) $transient->no_update=[];
  if (!isset($transient->no_update[AYIG_BASENAME])) {
   $transient->no_update[AYIG_BASENAME]=(object)[
    'id'=>'https://github.com/'.self::OWNER.'/'.self::REPO,
    'slug'=>'asenka-yootheme-image-guard',
    'plugin'=>AYIG_BASENAME,
    'new_version'=>AYIG_VERSION,
    'url'=>'https://github.com/'.self::OWNER.'/'.self::REPO,
   ];
  }
  return $transient;
 }
 static function info($result,$action,$args){
  if($action!=='plugin_information'||empty($args->slug)||$args->slug!=='asenka-yootheme-image-guard')return $result;
  $r=self::api();if(is_wp_error($r))return $result;
  return (object)['name'=>'Asenka Guard','slug'=>'asenka-yootheme-image-guard','version'=>$r['version'],'author'=>'Asenka Interactive','homepage'=>'https://github.com/'.self::OWNER.'/'.self::REPO,'download_link'=>$r['zip'],'sections'=>['description'=>'YOOtheme Pro image handler exposure and suspicious upload review.','changelog'=>esc_html($r['notes'])]];
 }
 static function normalize($source,$remote_source,$upgrader,$hook_extra){
  if(empty($hook_extra['plugin'])||$hook_extra['plugin']!==AYIG_BASENAME)return $source;
  $target=trailingslashit($remote_source).'asenka-yootheme-image-guard';
  if(untrailingslashit($source)===untrailingslashit($target))return $source;
  if(file_exists($target))return new WP_Error('ayig_destination_exists','Source normalization target already exists');
  global $wp_filesystem;
  if(!$wp_filesystem||!$wp_filesystem->move($source,$target))return new WP_Error('ayig_rename_failed','Could not normalize plugin ZIP root directory');
  return $target;
 }
 static function menu(){add_management_page('Asenka Guard Updates','Image Guard Updates','update_plugins','ayig-updates',[__CLASS__,'page']);}
 static function links($links){
  array_unshift($links,'<a href="'.esc_url(admin_url('admin.php?page=asenka-yootheme-image-guard')).'">Dashboard</a>','<a href="https://github.com/Asenka-Dev-Team/Asenka-Guard" target="_blank" rel="noopener noreferrer">GitHub</a>');
  return $links;
 }
 static function refresh(){if(!current_user_can('update_plugins'))wp_die('Forbidden',403);check_admin_referer('ayig_refresh');delete_transient(self::CACHE);delete_site_transient('update_plugins');wp_update_plugins();wp_safe_redirect(Asenka_YOOtheme_Image_Guard::admin_url('updates'));exit;}
 static function page(){echo '<div class="wrap">';self::panel();echo '</div>'; }
 static function panel(){if(!current_user_can('update_plugins'))return;$r=self::api();echo '<div class="ayig-updates"><h2>GitHub Releases</h2><p>Installed version: <strong>'.esc_html(AYIG_VERSION).'</strong></p><p>Repository: <a href="'.esc_url('https://github.com/'.self::OWNER.'/'.self::REPO).'" target="_blank" rel="noopener">'.esc_html(self::OWNER.'/'.self::REPO).'</a></p>';
  if(is_wp_error($r))echo '<div class="notice notice-warning"><p>'.esc_html($r->get_error_message()).'. Publish a stable GitHub Release to activate automatic updates.</p></div>';
  else {echo '<p>Latest release: <strong>'.esc_html($r['tag']).'</strong> — '.(version_compare($r['version'],AYIG_VERSION,'>')?'Update available':'Up to date').'</p><p>Last checked: '.esc_html(gmdate('Y-m-d H:i:s',$r['checked'])).' UTC</p><p><a href="'.esc_url($r['url']).'" target="_blank" rel="noopener">View release notes</a></p>';}
  $transient=get_site_transient('update_plugins');
  $record=is_object($transient)&&isset($transient->response[AYIG_BASENAME])?$transient->response[AYIG_BASENAME]:null;
  $native=is_object($record)?($record->new_version??$record->version??''):(is_array($record)?($record['new_version']??$record['version']??''):'');
  echo '<p>WordPress update registration: <strong>'.($native?esc_html('Available: '.$native):'No native update currently registered').'</strong></p>';
  if (function_exists('wp_is_auto_update_enabled_for_type') && !wp_is_auto_update_enabled_for_type('plugin')) {
   echo '<p><strong>Automatic updates:</strong> Disabled site-wide by WordPress configuration, hosting, or another plugin. The Plugins-page toggle cannot appear until enabled globally.</p>';
  } else {
   $enabled=(array)get_site_option('auto_update_plugins',[]);
   echo '<p><strong>Asenka Guard auto-updates:</strong> '.(in_array(AYIG_BASENAME,$enabled,true)?'Enabled':'Disabled').'. Change this in Plugins &rarr; Automatic Updates.</p>';
  }

  if($native && version_compare($native,AYIG_VERSION,'>')){
   $link=wp_nonce_url(admin_url('update.php?action=upgrade-plugin&plugin='.rawurlencode(AYIG_BASENAME)),'upgrade-plugin_'.AYIG_BASENAME);
   echo '<p><a class="button button-primary" href="'.esc_url($link).'">Update now through WordPress</a> <a href="'.esc_url(admin_url('plugins.php')).'">View Plugins page</a></p>';
  }elseif(!is_wp_error($r) && version_compare($r['version'],AYIG_VERSION,'>')){
   echo '<p>GitHub has a newer release, but WordPress has not registered it. Click Check for Updates to refresh the native update check.</p>';
  }
  echo '<form method="post" action="'.esc_url(admin_url('admin-post.php')).'"><input type="hidden" name="action" value="ayig_refresh">';wp_nonce_field('ayig_refresh');submit_button('Check for Updates');echo '</form></div>';
 }
}
