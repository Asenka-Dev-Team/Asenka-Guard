<?php
if (!defined('ABSPATH')) exit;
final class Asenka_YOOtheme_Image_Guard {
 const VERSION=AYIG_VERSION; const HISTORY="ayig_scan_history"; const OPTION='ayig_findings'; const LOG='ayig_audit'; const IGNORED='ayig_ignored_files'; const MONITOR='ayig_monitor_settings'; const BASELINE='ayig_yootheme_baseline'; const ALERT_HASH='ayig_last_alert_fingerprint';
 static function init(){add_action('admin_menu',[__CLASS__,'menu']);add_action('admin_post_ayig',[__CLASS__,'action']);add_action('admin_post_ayig_view',[__CLASS__,'view']);add_action('admin_post_ayig_download',[__CLASS__,'download']);add_action('admin_enqueue_scripts',[__CLASS__,'assets']);add_filter('admin_footer_text',[__CLASS__,'footer']);add_filter('update_footer',[__CLASS__,'footer_version'],20); add_action('ayig_monitor_scan',[__CLASS__,'scheduled_scan']);add_action('admin_init',[__CLASS__,'ensure_schedule']); if(defined('WP_CLI') && WP_CLI) self::cli();}
 static function menu(){
  add_management_page('Asenka Guard','Asenka Guard','manage_options','asenka-yootheme-image-guard',[__CLASS__,'page']);
  // Give Image Guard its own recognizable security icon in the main WP admin sidebar.
  $svg='<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 64 64"><path d="M32 5 54 13v16c0 16-9 25-22 31C19 54 10 45 10 29V13L32 5Z" fill="none" stroke="#a7aaad" stroke-width="5"/><path d="m22 32 7 7 14-16" fill="none" stroke="#a7aaad" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  add_menu_page('Asenka Guard','Asenka Guard','manage_options','asenka-yootheme-image-guard',[__CLASS__,'page'],'data:image/svg+xml;base64,'.base64_encode($svg),81);
 }
 /** Opt-in WP-Cron monitoring. Scheduled scans run only when WordPress cron executes. */
 static function monitor_settings(){return wp_parse_args((array)get_option(self::MONITOR,[]),['enabled'=>false,'frequency'=>'daily','scope'=>'uploads','email'=>get_option('admin_email'),'notify'=>true]);}
 static function ensure_schedule(){
  $cfg=self::monitor_settings();$next=wp_next_scheduled('ayig_monitor_scan');
  if(empty($cfg['enabled'])){if($next)wp_clear_scheduled_hook('ayig_monitor_scan');return;}
  $frequency=$cfg['frequency']==='weekly'?'weekly':'daily';
  if($next && wp_get_schedule('ayig_monitor_scan')!==$frequency){wp_clear_scheduled_hook('ayig_monitor_scan');$next=false;}
  if(!$next)wp_schedule_event(time()+300,$frequency,'ayig_monitor_scan');
 }
 static function save_monitor($post){
  $frequency=isset($post['frequency'])&&$post['frequency']==='weekly'?'weekly':'daily';
  $scope=isset($post['scope'])&&$post['scope']==='site'?'site':'uploads';
  $email=sanitize_email(wp_unslash($post['email']??''));if(!is_email($email))throw new RuntimeException('Enter a valid notification email address.');
  $cfg=['enabled'=>!empty($post['enabled']),'frequency'=>$frequency,'scope'=>$scope,'email'=>$email,'notify'=>!empty($post['notify'])];
  update_option(self::MONITOR,$cfg,false);wp_clear_scheduled_hook('ayig_monitor_scan');self::ensure_schedule();self::audit('monitor_settings','Changed scheduled scan preferences');
 }
 static function scheduled_scan(){
  $cfg=self::monitor_settings();if(empty($cfg['enabled']))return;
  $scope=$cfg['scope'];$started=time();
  try{
   $result=self::scan($scope);
   $history=(array)get_option(self::HISTORY,[]);$latest=end($history);
   $changes=$latest['changes']??[]; $new=(int)($changes['new']??0);$changed=(int)($changes['changed']??0);
   update_option('ayig_monitor_last',['at'=>$started,'scope'=>$scope,'state'=>empty($result['complete'])?'partial':'completed','visited'=>$result['visited'],'new'=>empty($result['complete'])?0:$new,'changed'=>empty($result['complete'])?0:$changed],false);
   if(empty($result['complete'])){$new=0;$changed=0;}
   if(!empty($cfg['notify']) && ($new || $changed || empty($result['complete']))){
    $fingerprint=hash('sha256',wp_json_encode([$scope,$new,$changed,$result['truncated'],array_keys(array_filter((array)get_option(self::OPTION,[]),static function($f)use($scope){return ($f['state']??'')==='active' && self::scan_scope($f)===$scope && in_array(($f['change_status']??''),['new','changed'],true);} ))]));
    if($fingerprint!==get_option(self::ALERT_HASH,'')){
     $body="Asenka Guard scheduled scan ($scope)\nNew findings: $new\nChanged findings: $changed\n".(empty($result['complete'])?"WARNING: Scan incomplete; previous results preserved.\n":'')."Review: ".self::admin_url($scope==='site'?'site':'results');
     if(wp_mail($cfg['email'],'[Asenka Guard] Scan findings on '.wp_parse_url(home_url(),PHP_URL_HOST),$body))update_option(self::ALERT_HASH,$fingerprint,false);
    }
   }
  }catch(Throwable $e){update_option('ayig_monitor_last',['at'=>$started,'scope'=>$scope,'state'=>'failed','error'=>substr($e->getMessage(),0,200)],false);if(!empty($cfg['notify']))wp_mail($cfg['email'],'[Asenka Guard] Scheduled scan failed','The '. $scope .' scan failed. Review the plugin dashboard and server logs.');}
 }
 /** Snapshot YOOtheme's own PHP/template/JS files. Not a trusted vendor checksum. */
 static function yootheme_paths(){
  $dirs=[];
  foreach(wp_get_themes() as $slug=>$theme){if(stripos($slug,'yootheme')!==false||stripos($theme->get('Name'),'yootheme')!==false)$dirs[]=$theme->get_stylesheet_directory();}
  if(!function_exists('get_plugins'))require_once ABSPATH.'wp-admin/includes/plugin.php';
  foreach(get_plugins() as $file=>$plugin){if(stripos($file,'yootheme')!==false||stripos($plugin['Name'],'yootheme')!==false)$dirs[]=WP_PLUGIN_DIR.'/'.dirname($file);}
  return array_values(array_unique(array_filter($dirs,'is_dir')));
 }
 static function integrity_inventory(){
  $entries=[];$count=0;$partial=false;
  foreach(self::yootheme_paths() as $root){
   $realroot=realpath($root);if(!$realroot)continue;
   $it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($realroot,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::LEAVES_ONLY);
   foreach($it as $file){if(++$count>25000){$partial=true;break 2;}if(!$file->isFile()||$file->isLink())continue;
    $real=realpath($file->getPathname());if(!$real||!self::within($real,$realroot))continue;
    if(!preg_match('/\.(?:php|js|json|twig|html|htm|blade\.php)$/i',$real))continue;
    if($file->getSize()>5242880)continue;
    $hash=@hash_file('sha256',$real);if($hash)$entries[wp_normalize_path($real)]=['sha256'=>$hash,'size'=>$file->getSize()];
   }
  }
  ksort($entries);return ['files'=>$entries,'partial'=>$partial,'visited'=>$count];
 }
 static function integrity_report(){
  $baseline=(array)get_option(self::BASELINE,[]);$current=self::integrity_inventory();$changes=[];
  if(!isset($baseline['files']))return ['state'=>'not-baselined','changes'=>[],'current'=>$current];
  if(!empty($current['partial'])||!empty($baseline['partial']))return ['state'=>'incomplete','changes'=>[],'current'=>$current];
  foreach($current['files'] as $path=>$meta)if(!isset($baseline['files'][$path]))$changes[]=['path'=>$path,'type'=>'Added'];elseif(!hash_equals((string)$baseline['files'][$path]['sha256'],$meta['sha256']))$changes[]=['path'=>$path,'type'=>'Modified'];
  foreach($baseline['files'] as $path=>$meta)if(!isset($current['files'][$path]))$changes[]=['path'=>$path,'type'=>'Removed'];
  return ['state'=>'compared','changes'=>$changes,'current'=>$current,'baseline_at'=>$baseline['at']??0];
 }
 static function capture_baseline(){
  $inventory=self::integrity_inventory();if(!$inventory['files']||$inventory['partial'])throw new RuntimeException('No complete YOOtheme file inventory available; baseline not saved.');
  $inventory['at']=time();update_option(self::BASELINE,$inventory,false);self::audit('integrity_baseline','Captured '.count($inventory['files']).' file hashes');
 }
 static function monitor_panel(){
  $cfg=self::monitor_settings();$last=(array)get_option('ayig_monitor_last',[]);$next=wp_next_scheduled('ayig_monitor_scan');
  echo '<section class="ayig-monitor"><h2>Scheduled monitoring</h2><p>Opt-in WP-Cron scanning. Runs when WordPress cron is triggered, not at a guaranteed wall-clock time. Large scans can hit PHP time limits; use WP-CLI/server cron for reliable large-site scanning.</p>';
  echo '<form action="'.esc_url(admin_url('admin-post.php')).'" method="post">';wp_nonce_field('ayig');echo '<input type="hidden" name="action" value="ayig"><input type="hidden" name="operation" value="save_monitor"><input type="hidden" name="tab" value="dashboard">';
  echo '<p><label><input type="checkbox" name="enabled" value="1" '.checked(!empty($cfg['enabled']),true,false).'> Enable scheduled scans</label></p><p><label>Frequency <select name="frequency"><option value="daily" '.selected($cfg['frequency'],'daily',false).'>Daily</option><option value="weekly" '.selected($cfg['frequency'],'weekly',false).'>Weekly</option></select></label> &nbsp; <label>Scope <select name="scope"><option value="uploads" '.selected($cfg['scope'],'uploads',false).'>Uploads</option><option value="site" '.selected($cfg['scope'],'site',false).'>Site (may time out)</option></select></label></p>';
  echo '<p><label><input type="checkbox" name="notify" value="1" '.checked(!empty($cfg['notify']),true,false).'> Email on new/changed findings or incomplete scans</label></p><p><label>Alert email <input type="email" name="email" value="'.esc_attr($cfg['email']).'" required></label></p><p><button type="submit" class="button button-primary">Save monitoring settings</button></p></form>';
  echo '<p>Next run: <strong>'.($next?esc_html(wp_date('Y-m-d H:i',$next)):'Not scheduled').'</strong> · Last run: <strong>'.(!empty($last['at'])?esc_html(wp_date('Y-m-d H:i',(int)$last['at'])).' — '.esc_html($last['state']):'Never').'</strong></p></section>';
 }
 static function integrity_panel(){
  $r=self::integrity_report();$base=(array)get_option(self::BASELINE,[]);
  echo '<section class="ayig-monitor"><h2>YOOtheme file integrity</h2><p>Local change monitoring of YOOtheme PHP, templates and JavaScript. <strong>This is NOT a vendor-authenticated integrity check.</strong> Capture a baseline only after verifying the installation is clean. Theme/plugin updates will legitimately change files.</p>';
  echo '<p>Baseline: <strong>'.(!empty($base['at'])?esc_html(wp_date('Y-m-d H:i',(int)$base['at'])):'Not captured').'</strong> · Files inventoried: '.esc_html((string)count($r['current']['files'])).'</p>';
  if($r['state']==='incomplete')echo '<p class="ayig-summary-warning">Inventory limit reached: comparison unavailable.</p>';
  elseif($r['state']==='compared'){
   echo '<p><strong>'.count($r['changes']).' changed/added/removed files</strong> since baseline.</p>';
   if($r['changes']){echo '<div class="ayig-integrity-list"><table class="widefat striped"><thead><tr><th>Change</th><th>Path</th></tr></thead><tbody>';foreach(array_slice($r['changes'],0,200) as $c)echo '<tr><td>'.esc_html($c['type']).'</td><td><code>'.esc_html($c['path']).'</code></td></tr>';echo '</tbody></table></div>';}
  }
  echo '<form action="'.esc_url(admin_url('admin-post.php')).'" method="post">';wp_nonce_field('ayig');echo '<input type="hidden" name="action" value="ayig"><input type="hidden" name="operation" value="capture_baseline"><input type="hidden" name="tab" value="integrity"><button type="submit" class="button" data-confirm="Replace the baseline only after verifying the YOOtheme installation is clean. Continue?">'.(empty($base['at'])?'Capture reviewed baseline':'Replace baseline after verification').'</button></form></section>';
 }
 static function dashboard_panel(){
  $findings=(array)get_option(self::OPTION,[]);$active=0;$high=0;$q=0;foreach($findings as $f){if(($f['state']??'')==='quarantined')$q++;if(($f['state']??'')==='active'){$active++;if(in_array(($f['severity']??''),['high','critical'],true))$high++;}}
  echo '<div class="ayig-metrics"><div><strong>'.esc_html((string)$active).'</strong><span>Active findings</span></div><div><strong>'.esc_html((string)$high).'</strong><span>High / Critical</span></div><div><strong>'.esc_html((string)$q).'</strong><span>Quarantined</span></div><div><strong>'.esc_html((string)count(self::versions())).'</strong><span>YOOtheme components</span></div></div>';
  foreach(['uploads'=>'Uploads','site'=>'Site'] as $scope=>$label){$last=(array)get_option('ayig_last_scan_'.$scope,[]);echo '<p><strong>'.esc_html($label).' scan:</strong> '.(!empty($last['at'])?esc_html(wp_date('Y-m-d H:i',(int)$last['at'])).' · '.esc_html((string)$last['active']).' active findings'.(empty($last['complete'])?' · INCOMPLETE':''):'Never run').'</p>';}
  self::monitor_panel();
 }
 static function roots($scope='uploads'){return $scope==='site'?[ABSPATH]:[WP_CONTENT_DIR.'/uploads'];}
 static function scan_scope($f){return ($f['scope']??'uploads')==='site'?'site':'uploads';}
 static function ignored(){return (array)get_option(self::IGNORED,[]);}
 static function versions(){ $out=[]; foreach(wp_get_themes() as $slug=>$theme){if(stripos($slug,'yootheme')!==false || stripos($theme->get('Name'),'yootheme')!==false){$v=$theme->get('Version');$out[]=['type'=>'theme','name'=>$theme->get('Name'),'version'=>$v,'status'=>self::status($v)];}} foreach(get_plugins() as $path=>$plugin){if(stripos($path,'yootheme')!==false || stripos($plugin['Name'],'yootheme')!==false){$v=$plugin['Version'];$out[]=['type'=>'plugin','name'=>$plugin['Name'],'version'=>$v,'status'=>self::status($v)];}}return $out; }
 /** Vendor checksums are advisory; no response or unknown file never means clean. */
 static function trusted_checksums($scope){
  if($scope!=='site')return ['core'=>[], 'plugins'=>[]];
  global $wp_version;
  $core=[];$locale=get_locale();$key='ayig_core_md5_'.md5($wp_version.'|'.$locale);
  $cached=get_transient($key);
  if($cached===false){
   if(!function_exists('get_core_checksums'))require_once ABSPATH.'wp-admin/includes/update.php';
   $received=get_core_checksums($wp_version,$locale);
   $cached=is_array($received)?$received:[];
   set_transient($key,$cached,12*HOUR_IN_SECONDS);
  }
  if(is_array($cached))$core=$cached;
  return ['core'=>$core,'plugins'=>[]];
 }
 /** Only query the fixed wordpress.org endpoint for exact installed WordPress.org plugin versions. */
 static function plugin_checksum_for($path,&$cache,&$requests){
  $relative=ltrim(substr(wp_normalize_path($path),strlen(rtrim(wp_normalize_path(WP_PLUGIN_DIR),'/'))),'/');
  if(!$relative || strpos($relative,'../')!==false || strpos($relative,'\\')!==false)return null;
  $parts=explode('/',$relative);if(count($parts)<2)return null;
  $slug=$parts[0];if(!preg_match('/^[a-z0-9_-]+$/D',$slug))return null;
  if(!isset($cache[$slug])){
   $cache[$slug]=['files'=>[],'verified'=>false];
   if(!function_exists('get_plugins'))require_once ABSPATH.'wp-admin/includes/plugin.php';
   $pluginData=null;
   foreach(get_plugins() as $file=>$data){if(strpos($file,$slug.'/')===0){$pluginData=$data;break;}}
   if(!$pluginData)return null;
   $version=(string)($pluginData['Version']??'');
   if(!preg_match('/^[0-9][a-zA-Z0-9._-]*$/D',$version))return null;
   $transient='ayig_plugin_md5_'.md5($slug.'|'.$version);
   $cached=get_transient($transient);
   if($cached===false){
    if($requests>=8)return null;
    $requests++;
    $url='https://downloads.wordpress.org/plugin-checksums/'.rawurlencode($slug).'/'.rawurlencode($version).'.json';
    $response=wp_remote_get($url,['timeout'=>3,'redirection'=>0]);
    $json=!is_wp_error($response)&&wp_remote_retrieve_response_code($response)===200?json_decode(wp_remote_retrieve_body($response),true):null;
    $cached=is_array($json)&&isset($json['files'])&&is_array($json['files'])?$json['files']:[];
    set_transient($transient,$cached,12*HOUR_IN_SECONDS);
   }
   if(is_array($cached)&&$cached)$cache[$slug]=['files'=>$cached,'verified'=>true];
  }
  $checks=$cache[$slug]['files'];$key=implode('/',array_slice($parts,1));
  if(!isset($checks[$key]))return null;
  $values=(array)$checks[$key];
  return ['valid'=>in_array(md5_file($path),$values,true),'slug'=>$slug];
 }
 static function known_placeholder($path,$size,$data){
  if(strtolower(basename($path))!=='index.php'||$size>512)return false;
  $trim=trim($data);
  if($trim==='')return true;
  return (bool)preg_match('~^<\?php\s*(?:(?://|/\*)\s*Silence is golden\.?\s*(?:\*/)?\s*)?(?:\?>)?\s*$~i',$trim);
 }
 static function status($v){if(!preg_match('/^\d+\.\d+\.\d+/',$v))return 'unknown';return version_compare($v,'5.0.0','>=') && version_compare($v,'5.0.53','<')?'VULNERABLE':'not in known affected range';}
 static function signatures($data,$extension){$hits=[]; $rules=['php_tag'=>'/<\?(?:php|=)/i','execution'=>'/\b(?:eval|assert|shell_exec|passthru|system|proc_open|popen)\s*\(/i','obfuscation'=>'/\b(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(/i','request_execution'=>'/(?:\$_(?:POST|GET|REQUEST|COOKIE)\s*\[.{0,100}\]).{0,200}(?:eval|system|shell_exec)|(?:eval|system|shell_exec)\s*\(.{0,150}\$_(?:POST|GET|REQUEST|COOKIE)/is','image_polyglot'=>'/<\?(?:php|=)/i'];foreach($rules as $id=>$re){if($id==='image_polyglot' && !in_array($extension,['png','jpg','jpeg','gif','webp','avif','bmp','ico'],true))continue;if($id==='php_tag' && !in_array($extension,['png','jpg','jpeg','gif','webp','avif','bmp','ico','svg','txt','dat'],true))continue;if(preg_match($re,$data))$hits[]=$id;}return $hits;}
 /** Scans uploads or WordPress installation. A site scan does not follow symlinks. */
 static function scan($scope='uploads'){
  if(!in_array($scope,['uploads','site'],true))throw new RuntimeException('Invalid scan scope');
  $findings=[];$count=0;$limit=150000;$truncated=false;$scanErrors=[];$readFailures=0;$ignored=self::ignored();$trusted=self::trusted_checksums($scope);$pluginChecks=[];$pluginRequests=0;$verification=['core_verified'=>0,'core_modified'=>0,'plugin_verified'=>0,'plugin_modified'=>0,'unverified'=>0,'placeholders'=>0];
  foreach(self::roots($scope) as $root){
   if(!is_dir($root)||!is_readable($root)){$scanErrors[]='Scan root unavailable: '.$root;continue;}
   $directory=new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS);
   $filter=new RecursiveCallbackFilterIterator($directory,function($current) use($scope){
    if($current->isLink())return false;
    if($current->isDir()){
     $path=wp_normalize_path($current->getPathname());
     if($scope==='site' && (wp_normalize_path($current->getPathname())===rtrim(wp_normalize_path(WP_CONTENT_DIR.'/uploads'),'/') || preg_match('~/(?:\.git|node_modules|vendor|cache)(?:/|$)~i',$path)||strpos($path,wp_normalize_path(dirname(ABSPATH).'/asenka-yootheme-image-guard-quarantine'))===0))return false;
    }
    return true;
   });
   $iter=new RecursiveIteratorIterator($filter,RecursiveIteratorIterator::LEAVES_ONLY);
   foreach($iter as $file){
    if(++$count>$limit){$truncated=true;break 2;}
    if(!$file->isFile()||$file->isLink())continue;
    $path=$file->getPathname();$real=realpath($path);
    if(!$real||!self::within($real,$root))continue;if($scope==='site'&&self::within($real,WP_CONTENT_DIR.'/uploads'))continue;
    $ext=strtolower(pathinfo($path,PATHINFO_EXTENSION));
    $executable=self::is_executable($path);$inUploads=self::within($real,WP_CONTENT_DIR.'/uploads');
    $size=$file->getSize();
    // Full site scans focus on executable PHP and suspicious media; ordinary assets are skipped.
    if($scope==='site'&&!$executable&&!in_array($ext,['png','jpg','jpeg','gif','webp','avif','svg','ico','pht','phtml','dat','bin','txt'],true) && strtolower(basename($path))!=='wp-blog.php')continue;
    $data=$size<=2097152?@file_get_contents($path):@file_get_contents($path,false,null,0,131072);
    if($data===false){$readFailures++;continue;}
    if(self::known_placeholder($path,$size,$data)){$verification['placeholders']++;continue;}
    $evidence=Asenka_Guard_Detector::inspect($data,$ext,$size<=2097152);
    // Only the detector should inspect image bytes: arbitrary entropy can resemble PHP.
    $hits=array_merge(Asenka_Guard_Detector::media($ext)?[]:self::signatures($data,$ext),$evidence['signals']);
    // An image with embedded PHP marker alone remains a review finding; plain images without code are not findings.
    if(Asenka_Guard_Detector::media($ext) && !in_array('embedded_php',$hits,true)){
      $hits=array_values(array_diff($hits,['php_tag','image_polyglot','execution','obfuscation','request_execution']));
    }
    if(strtolower(basename($path))==='wp-blog.php' && $scope==='site')$hits[]='unusual_root_php';
    $hits=array_values(array_unique($hits));
    if($executable&&$inUploads)$hits[]='executable_in_writable_area';
    if($executable&&$inUploads&&preg_match('~^tmp_[0-9]+\.php$~i',basename($path)))$hits[]='observed_tmp_php_pattern';
    if(!$hits)continue;
    if($executable&&strtolower(basename($path))==='index.php'&&$size<=512&&preg_match('~^\s*<\?php\s*(?:(?://|/\*)\s*Silence is golden\.?\s*(?:\*/)?\s*)?(?:\?>)?\s*$~i',$data))$hits=['standard_index_placeholder'];
    // PHP in core, themes and plugins is ordinary. Only retain stronger code indicators there.
    if($scope==='site'&&!$inUploads && !array_intersect($hits,['request_execution','request_shell_execution','request_code_execution','goto_exec_obfuscation','image_type_mismatch','embedded_php','unusual_root_php']) && !(in_array('execution',$hits,true)&&in_array('obfuscation',$hits,true)))continue;
    // Verify only exact vendor-provided file hashes. Unknown/unreachable => retain finding.
    if($scope==='site'){
     $normalized=wp_normalize_path($real);$rootPath=rtrim(wp_normalize_path(ABSPATH),'/').'/';
     $rel=strpos($normalized,$rootPath)===0?substr($normalized,strlen($rootPath)):'';
     if($rel!=='' && isset($trusted['core'][$rel])){
      if(hash_equals(strtolower((string)$trusted['core'][$rel]),md5_file($real))){$verification['core_verified']++;continue;}
      $hits[]='core_checksum_mismatch';$verification['core_modified']++;
     }elseif(self::within($real,WP_PLUGIN_DIR)){
      $check=self::plugin_checksum_for($real,$pluginChecks,$pluginRequests);
      if(is_array($check)){
       if($check['valid']){$verification['plugin_verified']++;continue;}
       $hits[]='plugin_checksum_mismatch';$verification['plugin_modified']++;
      }else{$verification['unverified']++;}
     }
    }
    $id=hash('sha256',$real);$sha=@hash_file('sha256',$real);if(!$sha)continue;
    if(isset($ignored[$id]) && hash_equals((string)$ignored[$id]['sha256'],$sha))continue;
    if(isset($ignored[$id]))unset($ignored[$id]); // Any file modification revokes its ignore rule.
    $findings[$id]=['id'=>$id,'path'=>$real,'size'=>$size,'mtime'=>$file->getMTime(),'sha256'=>$sha,'permissions'=>substr(sprintf('%o',$file->getPerms()),-4),'confidence'=>self::confidence($hits),'signals'=>array_values(array_unique($hits)),'severity'=>self::classify($hits,$executable),'state'=>'active','scope'=>$scope,'detected_type'=>$evidence['detected_type'],'inspection'=>$evidence['inspection']];
   }
  }
  $previous=(array)get_option(self::OPTION,[]);
  $complete=!$truncated && !$scanErrors && $readFailures===0;
  $prior_active=[];foreach($previous as $id=>$old){if(($old['state']??'')==='active' && self::scan_scope($old)===$scope)$prior_active[$id]=$old['sha256']??'';}
  foreach($findings as $id=>&$finding)$finding['change_status']=!isset($prior_active[$id])?'new':($prior_active[$id]===$finding['sha256']?'previously-detected':'changed');unset($finding);
  $changes=['new'=>0,'changed'=>0,'previously-detected'=>0];foreach($findings as $finding)$changes[$finding['change_status']]++;
  foreach($previous as $old_id=>$old){
   if(($old['state']??'active')==='quarantined'||($old['state']??'active')==='deleted')$findings[$old_id]=$old;
   elseif(self::scan_scope($old)!==$scope && ($old['state']??'active')==='active')$findings[$old_id]=$old;
  }
  if($complete){
   update_option(self::IGNORED,$ignored,false);
   update_option(self::OPTION,$findings,false);
  }
  $active=count(array_filter($complete?$findings:$previous,static function($f)use($scope){return ($f['state']??'')==='active' && self::scan_scope($f)===$scope;}));
  update_option('ayig_last_scan_'.$scope,['at'=>time(),'visited'=>$count,'active'=>$active,'truncated'=>$truncated,'complete'=>$complete,'read_failures'=>$readFailures,'errors'=>$scanErrors,'verification'=>$verification],false);
  if($scope==='uploads')update_option('ayig_last_scan',['at'=>time(),'visited'=>$count,'active'=>$active,'truncated'=>$truncated,'complete'=>$complete,'read_failures'=>$readFailures,'errors'=>$scanErrors,'verification'=>$verification],false);
  $history=(array)get_option(self::HISTORY,[]);
  $history[]=['at'=>time(),'scope'=>$scope,'visited'=>$count,'active'=>$active,'truncated'=>$truncated,'complete'=>$complete,'read_failures'=>$readFailures,'errors'=>$scanErrors,'changes'=>$changes];
  update_option(self::HISTORY,array_slice($history,-30),false);
  self::audit('scan_'.$scope,($complete?'Complete':'INCOMPLETE').'; '.$active.' retained active findings; '.$count.' files visited');
  return ['findings'=>$complete?$findings:$previous,'visited'=>$count,'truncated'=>$truncated,'complete'=>$complete,'read_failures'=>$readFailures,'errors'=>$scanErrors,'active'=>$active];
 }
 static function ignore_file($id){
  $items=(array)get_option(self::OPTION,[]);
  if(!isset($items[$id])||($items[$id]['state']??'')!=='active')throw new RuntimeException('Only active findings can be ignored');
  $f=$items[$id];if(!self::safe_existing($f['path'],$f['sha256']))throw new RuntimeException('File changed or is no longer safe to ignore; rescan first');
  $ignored=self::ignored();$ignored[$id]=['path'=>$f['path'],'sha256'=>$f['sha256'],'scope'=>self::scan_scope($f),'ignored_at'=>time()];
  update_option(self::IGNORED,$ignored,false);unset($items[$id]);update_option(self::OPTION,$items,false);self::audit('ignore',$f['path']);
 }
 static function unignore_file($id){
  $ignored=self::ignored();if(!isset($ignored[$id]))throw new RuntimeException('Ignored file not found');
  $path=$ignored[$id]['path'];unset($ignored[$id]);update_option(self::IGNORED,$ignored,false);self::audit('unignore',$path);
 }
 /** A heuristic triage score, not a malware verdict. Extension alone never means HIGH. */
 static function classify($hits,$executable){
  if(in_array('standard_index_placeholder',$hits,true))return 'low';
  if(in_array('core_checksum_mismatch',$hits,true)||in_array('jpeg_appended_php',$hits,true))return 'high';
  if(in_array('plugin_checksum_mismatch',$hits,true))return 'review';
  $request=in_array('request_execution',$hits,true);
  $exec=in_array('execution',$hits,true);
  $obfuscated=in_array('obfuscation',$hits,true);
  $polyglot=in_array('image_polyglot',$hits,true);
  $tmp=in_array('observed_tmp_php_pattern',$hits,true);
  if(array_intersect($hits,['request_shell_execution','request_code_execution']) && ($exec || $obfuscated))return 'critical';
  if($request && ($exec || $obfuscated || $polyglot))return 'critical';
  if(array_intersect($hits,['goto_exec_obfuscation','request_shell_execution','request_code_execution']))return 'high';
  if(in_array('compressed_payload',$hits,true) && ($exec || in_array('embedded_php',$hits,true)))return 'high';
  if($request || ($exec && $obfuscated) || ($tmp && ($exec || $obfuscated)))return 'high';
  if($tmp || ($polyglot && ($exec || $obfuscated)))return 'high';
  if($executable || $polyglot || $exec || $obfuscated || array_intersect($hits,['image_type_mismatch','compressed_uninspected','unusual_root_php','embedded_php']))return 'review';
  return 'low';
 }
 static function within($path,$root){$base=realpath($root);return $base && strncmp($path,$base.DIRECTORY_SEPARATOR,strlen($base)+1)===0;}
 /** Diagnostic only: local filesystem checks cannot establish HTTP reachability. */
 static function quarantine_diagnostics($create=false){
  $dir=apply_filters('ayig_quarantine_path',dirname(ABSPATH).'/asenka-yootheme-image-guard-quarantine');
  $result=['path'=>$dir,'state'=>'unknown','notes'=>[]];
  if(!is_string($dir)||$dir===''||$dir[0]!=='/'){$result['state']='blocked';$result['notes'][]='An absolute quarantine path is required.';return $result;}
  $normalized=wp_normalize_path($dir);$parent=realpath(dirname($dir));
  if(!$parent){$result['state']='blocked';$result['notes'][]='Parent directory does not exist.';return $result;}
  if(is_link($dir)||is_link(dirname($dir))){$result['state']='blocked';$result['notes'][]='A quarantine path component is a symbolic link.';return $result;}
  $candidate=wp_normalize_path($parent.'/'.basename($dir));
  foreach([ABSPATH,WP_CONTENT_DIR,WP_CONTENT_DIR.'/uploads'] as $webroot){
   $base=realpath($webroot);if(!$base)continue;
   $base=rtrim(wp_normalize_path($base),'/');
   if($candidate===$base||strpos($candidate,$base.'/')===0){$result['state']='blocked';$result['notes'][]='Quarantine directory is inside the WordPress installation or content directory.';return $result;}
  }
  if($create&&!is_dir($dir)){
   if(!@mkdir($dir,0700,false)&&!is_dir($dir)){$result['state']='blocked';$result['notes'][]='Cannot create private quarantine directory.';return $result;}
  }
  if(!is_dir($dir)){$result['state']='not-created';$result['notes'][]='Directory is not created yet; a write operation will attempt to create it.';return $result;}
  if(realpath($dir)!==realpath($parent).DIRECTORY_SEPARATOR.basename($dir)){$result['state']='blocked';$result['notes'][]='Quarantine path resolves unexpectedly.';return $result;}
  if($create&&!@chmod($dir,0700)){$result['notes'][]='Could not set directory permissions to 0700.';}
  $perms=@fileperms($dir);if($perms===false||($perms&0077)!==0){$result['state']='blocked';$result['notes'][]='Directory permissions are too broad or cannot be verified.';return $result;}
  if(!is_writable($dir)){$result['state']='blocked';$result['notes'][]='Directory is not writable.';return $result;}
  $result['state']='local-checks-passed';
  $result['notes'][]='Outside verified WordPress/content roots; restricted filesystem permissions.';
  $result['notes'][]='HTTP accessibility and server aliases cannot be established from these checks. Verify using server configuration.';
  return $result;
 }
 static function store(){
  $d=self::quarantine_diagnostics(true);
  if($d['state']!=='local-checks-passed')throw new RuntimeException('Quarantine storage failed safety checks: '.implode(' ', $d['notes']));
  return $d['path'];
 }
 static function confidence($signals){
  $signals=(array)$signals;
  if(in_array('standard_index_placeholder',$signals,true))return 'informational';
  if(in_array('request_execution',$signals,true)&&(in_array('execution',$signals,true)||in_array('obfuscation',$signals,true)))return 'strong-indicators';
  if(in_array('execution',$signals,true)&&in_array('obfuscation',$signals,true))return 'strong-indicators';
  if(array_intersect($signals,['request_shell_execution','request_code_execution','goto_exec_obfuscation']))return 'strong-indicators';
  if(in_array('observed_tmp_php_pattern',$signals,true)||in_array('jpeg_appended_php',$signals,true)||in_array('jpeg_metadata_php',$signals,true)||in_array('image_polyglot',$signals,true)||in_array('image_type_mismatch',$signals,true))return 'suspicious';
  return 'heuristic';
 }
 static function secure_file($path,$mode=0600){return @chmod($path,$mode) && ((@fileperms($path)&0077)===0);}
 static function safe_existing($path,$expected){
  if(!is_string($path)||!is_file($path)||is_link($path)||!self::allowed($path))return false;
  $actual=@hash_file('sha256',$path);return is_string($actual)&&hash_equals((string)$expected,$actual);
 }
 static function safe_destination($path){
  if(file_exists($path)||is_link($path)||!self::allowed($path))return false;
  $parent=realpath(dirname($path));return $parent && is_dir($parent) && !is_link(dirname($path)) && self::allowed($parent.'/'.basename($path));
 }
 static function audit($event,$message){$log=get_option(self::LOG,[]);$log[]= ['at'=>gmdate('c'),'user'=>get_current_user_id(),'event'=>$event,'detail'=>$message];update_option(self::LOG,array_slice($log,-300),false);}
 static function mutate($id,$operation){
  if(!preg_match('/^[a-f0-9]{64}$/D',(string)$id))throw new RuntimeException('Invalid finding ID');
  $items=get_option(self::OPTION,[]);if(!isset($items[$id]))throw new RuntimeException('Unknown finding');
  $f=&$items[$id];$dir=self::store();$manifest=$dir.'/'.$id.'.json';$dest=$dir.'/'.$id.'.quarantine';
  if($operation==='quarantine'){
   if($f['state']!=='active')throw new RuntimeException('Not active');if(self::scan_scope($f)==='site')throw new RuntimeException('Site scan findings are review-only; use controlled server remediation.');
   $path=$f['path'];if(self::scan_scope($f)==='site'&&!self::within($path,WP_CONTENT_DIR))throw new RuntimeException('Core/root files are review-only; quarantine through controlled server recovery');if(!self::safe_existing($path,$f['sha256']))throw new RuntimeException('File changed, missing or outside permitted scan roots');
   if(file_exists($dest)||is_link($dest)||file_exists($manifest)||is_link($manifest))throw new RuntimeException('Existing quarantine artifact: collision');
   $evidence=['original'=>$path,'sha256'=>$f['sha256'],'size'=>$f['size']??null,'mtime'=>$f['mtime']??null,'permissions'=>$f['permissions']??null,'signals'=>$f['signals']??[],'severity'=>$f['severity']??'review','confidence'=>$f['confidence']??self::confidence($f['signals']??[]),'quarantined_at'=>gmdate('c')];
   $tmp=$dir.'/'.$id.'.manifest-'.wp_generate_password(12,false,false).'.tmp';
   if(@file_put_contents($tmp,wp_json_encode($evidence),LOCK_EX)===false||!self::secure_file($tmp)){@unlink($tmp);throw new RuntimeException('Unable to write private manifest');}
   if(!@rename($tmp,$manifest)){@unlink($tmp);throw new RuntimeException('Manifest installation failed');}
   if(!@rename($path,$dest)){@unlink($manifest);throw new RuntimeException('Move failed');}
   $actual=@hash_file('sha256',$dest);
   if(!is_string($actual)||!hash_equals($f['sha256'],$actual)||!self::secure_file($dest)){
    if(!file_exists($path) && @rename($dest,$path)){@unlink($manifest);throw new RuntimeException('Quarantine verification failed; source restored');}
    throw new RuntimeException('Quarantine verification failed; file retained in quarantine pending administrator inspection');
   }
   $f['state']='quarantined';$f['quarantined_at']=time();
  }elseif($operation==='restore'){
   if($f['state']!=='quarantined')throw new RuntimeException('Not quarantined');
   if(!is_file($dest)||is_link($dest)||!self::safe_destination($f['path']))throw new RuntimeException('Restore blocked: quarantine file or target path is unsafe');
   $actual=@hash_file('sha256',$dest);if(!is_string($actual)||!hash_equals($f['sha256'],$actual))throw new RuntimeException('Quarantined file changed');
   if(!@rename($dest,$f['path']))throw new RuntimeException('Restore failed');
   $check=@hash_file('sha256',$f['path']);if(!is_string($check)||!hash_equals($f['sha256'],$check))throw new RuntimeException('Restore verification failed; inspect destination immediately');
   $f['state']='active';@unlink($manifest);
  }elseif($operation==='delete'){
   if($f['state']!=='quarantined')throw new RuntimeException('Quarantine before permanent deletion');
   if(!is_file($dest)||is_link($dest))throw new RuntimeException('Quarantine artifact missing or unsafe');
   $actual=@hash_file('sha256',$dest);if(!is_string($actual)||!hash_equals($f['sha256'],$actual))throw new RuntimeException('Quarantined file changed');
   if(!@unlink($dest))throw new RuntimeException('Delete failed');
   @unlink($manifest);$f['state']='deleted';
  }else throw new RuntimeException('Invalid operation');
  update_option(self::OPTION,$items,false);self::audit($operation,$f['path']);
 }
 static function allowed($path){foreach(self::roots('site') as $root)if(self::within($path,$root))return true;return false;}

 /** Stream unchanged finding bytes as an inert .bin attachment; never through a public uploads URL. */
 static function download(){
  if(!current_user_can('manage_options'))wp_die('Forbidden',403);
  $id=sanitize_text_field(wp_unslash($_GET['id']??''));
  if(!preg_match('/^[a-f0-9]{64}$/D',$id))wp_die('Invalid finding ID',400);
  check_admin_referer('ayig_download_'.$id);
  $items=(array)get_option(self::OPTION,[]);
  if(!isset($items[$id]))wp_die('Finding unavailable',404);
  $f=$items[$id];$state=$f['state']??'';
  if(!in_array($state,['active','quarantined'],true))wp_die('File unavailable for download',409);
  if($state==='active'){
   $file=$f['path'];
   if(!self::safe_existing($file,$f['sha256']))wp_die('File changed or path is unsafe',409);
  }else{
   // Quarantined files must be read only from verified private storage.
   $file=self::store().'/'.$id.'.quarantine';
   if(!is_file($file)||is_link($file))wp_die('Quarantined file unavailable',409);
  }
  $size=@filesize($file);
  if(!is_int($size)||$size<0||$size>8388608)wp_die('File exceeds the 8 MiB direct-download limit; use approved server-side analysis.',413);
  $sha=@hash_file('sha256',$file);
  if(!is_string($sha)||!hash_equals((string)$f['sha256'],$sha))wp_die('SHA-256 mismatch; download blocked',409);
  $fh=@fopen($file,'rb');if(!$fh)wp_die('Could not open file',500);
  $stat=@fstat($fh);
  if(!is_array($stat)||($stat['size']??-1)!==$size){fclose($fh);wp_die('File changed during preparation',409);}
  // An inert filename minimizes accidental execution on the receiving computer.
  $original=sanitize_file_name(basename($f['path']));
  $original=preg_replace('/[^a-zA-Z0-9._-]/','-',(string)$original);
  $original=substr($original?:'file',0,80);
  $name='asenka-guard-'.substr($id,0,12).'-'.$original.'.bin';
  while(ob_get_level()>0){@ob_end_clean();}
  nocache_headers();header('Content-Type: application/octet-stream');header('Content-Disposition: attachment; filename="'.$name.'"');header('X-Content-Type-Options: nosniff');header('Content-Security-Policy: sandbox');header('Content-Length: '.$size);header('Cache-Control: no-store, private');
  $remaining=$size;
  while($remaining>0&&!feof($fh)){
   $chunk=fread($fh,min(65536,$remaining));if($chunk===false||$chunk==='')break;
   echo $chunk;$remaining-=strlen($chunk);
  }
  fclose($fh);exit;
 }
 /** Site and software identity included in exported evidence manifests. */
 static function export_identity(){
  $host=(string)wp_parse_url(home_url(),PHP_URL_HOST);
  $host=preg_replace('/[^a-z0-9.-]/i','-',strtolower($host));
  if(!$host)$host='wordpress-site';
  $theme=wp_get_theme();$yoo=[];
  foreach(self::versions() as $component)$yoo[]=$component['name'].' '.$component['version'];
  return ['site_url'=>home_url('/'),'site_domain'=>$host,'wordpress_version'=>get_bloginfo('version'),'active_theme'=>$theme->get('Name'),'active_theme_version'=>$theme->get('Version'),'yootheme_versions'=>$yoo,'asenka_guard_version'=>self::VERSION];
 }
 static function evidence_export($ids){
  if(!class_exists('ZipArchive'))throw new RuntimeException('ZIP extension unavailable; cannot export evidence.');
  $items=(array)get_option(self::OPTION,[]);$ids=array_slice(array_unique($ids),0,50);
  if(!$ids)throw new RuntimeException('Select 1–50 findings for evidence export.');
  $zip=new ZipArchive();$temp=wp_tempnam('asenka-guard-evidence');if(!$temp)throw new RuntimeException('Unable to allocate export file');
  if($zip->open($temp,ZipArchive::OVERWRITE)!==true){@unlink($temp);throw new RuntimeException('Unable to initialize evidence ZIP');}
  $manifest=['generated_utc'=>gmdate('c'),'site'=>self::export_identity(),'scan_scope'=>'unknown','warning'=>'Untrusted files. Do not execute or restore on production without review.','files'=>[]];$total=0;$scopes=[];
  foreach($ids as $id){
   if(!preg_match('/^[a-f0-9]{64}$/D',$id)||!isset($items[$id]))continue;$f=$items[$id];$state=$f['state']??'';
   if($state!=='active' && $state!=='quarantined')continue;
   $file=$state==='active'?$f['path']:self::store().'/'.$id.'.quarantine';
   if(!is_file($file)||is_link($file)||($state==='active'&&!self::allowed($file)))continue;
   $size=@filesize($file);if(!is_int($size)||$size>2097152||$total+$size>12582912)continue;
   $sha=@hash_file('sha256',$file);if(!is_string($sha)||!hash_equals((string)$f['sha256'],$sha))continue;
   $data=@file_get_contents($file);if(!is_string($data))continue;
   $zip->addFromString('samples/'.$id.'.evidence',$data);$total+=strlen($data);
   $scope=self::scan_scope($f);$scopes[$scope]=true;
   $manifest['files'][]=['id'=>$id,'path'=>$f['path'],'sha256'=>$sha,'size'=>$size,'state'=>$state,'signals'=>$f['signals'],'scope'=>$scope];
  }
  $scope_label=count($scopes)===1?(string)key($scopes):'mixed';$manifest['scan_scope']=$scope_label;
  $zip->addFromString('manifest.json',wp_json_encode($manifest,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));$zip->close();
  if(!$manifest['files']){@unlink($temp);throw new RuntimeException('No eligible unchanged files under export limits.');}
  nocache_headers();header('Content-Type: application/zip');header('X-Content-Type-Options: nosniff');header('Content-Disposition: attachment; filename="asenka-guard-'.$manifest['site']['site_domain'].'-'.$scope_label.'-'.gmdate('Ymd-His').'-evidence.zip"');header('Content-Length: '.filesize($temp));readfile($temp);@unlink($temp);exit;
 }
 static function csv($scope='uploads',$metadata=true){
  if(!in_array($scope,['uploads','site'],true))$scope='uploads';
  $items=(array)get_option(self::OPTION,[]);
  $host=(string)wp_parse_url(home_url(),PHP_URL_HOST);
  $host=preg_replace('/[^a-z0-9.-]/i','-',strtolower($host));if(!$host)$host='wordpress-site';
  $filename='asenka-guard-'.$host.'-'.$scope.'-'.gmdate('Ymd-His').($metadata?'-report':'-findings').'.csv';
  header('Content-Type: text/csv; charset=utf-8');
  header('Content-Disposition: attachment; filename="'.$filename.'"');
  header('X-Content-Type-Options: nosniff');
  header('Cache-Control: no-store, private');
  $o=fopen('php://output','w');
  $safe=function($value){$value=(string)$value;return preg_match('/^[=+@\-\t\r\n]/',$value)?"'".$value:$value;};
  if($metadata){
   $theme=wp_get_theme();$yoothemes=self::versions();$yoo=[];
   foreach($yoothemes as $version)$yoo[]=$version['name'].' '.$version['version'];
   $fields=['Report'=>'Asenka Guard security scan','Site URL'=>home_url('/'),'Site domain'=>$host,'Scan scope'=>$scope,'Exported UTC'=>gmdate('c'),'WordPress version'=>get_bloginfo('version'),'Active theme'=>$theme->get('Name'),'Active theme version'=>$theme->get('Version'),'YOOtheme version(s)'=>$yoo?implode('; ',$yoo):'Not detected','Asenka Guard version'=>self::VERSION,'CSV format'=>'Report with metadata (use Findings-only for imports)'];
   foreach($fields as $key=>$value)fputcsv($o,[$safe($key),$safe($value)]);
   fputcsv($o,[]);
  }
  fputcsv($o,['Path','Scope','Severity','Confidence','State','Signals','Size','Modified UTC','SHA256','Permissions','Detected type','Inspection']);
  foreach($items as $f){if(self::scan_scope($f)!==$scope)continue;
   $row=[$f['path']??'',$scope,$f['severity']??'', $f['confidence']??self::confidence($f['signals']??[]),$f['state']??'',implode('|',$f['signals']??[]),$f['size']??'',isset($f['mtime'])?gmdate('c',$f['mtime']):'',$f['sha256']??'',$f['permissions']??'',$f['detected_type']??'',$f['inspection']??''];
   fputcsv($o,array_map($safe,$row));
  }
  fclose($o);exit;
 }

 static function admin_url($tab='results'){return add_query_arg(['page'=>'asenka-yootheme-image-guard','tab'=>$tab],admin_url('admin.php'));}
 static function assets($hook){if(!in_array($hook,['tools_page_asenka-yootheme-image-guard','toplevel_page_asenka-yootheme-image-guard'],true))return;wp_enqueue_style('ayig-admin',plugins_url('assets/admin.css',AYIG_FILE),[],self::VERSION);wp_enqueue_script('ayig-admin',plugins_url('assets/admin.js',AYIG_FILE),[],self::VERSION,true);}
 static function footer($text){if(empty($_GET['page'])||sanitize_key(wp_unslash($_GET['page']))!=='asenka-yootheme-image-guard')return $text;return 'Built by <a href="https://asenka.com" target="_blank" rel="noopener noreferrer">Asenka Interactive</a> · <a href="https://github.com/Asenka-Dev-Team/Asenka-Guard" target="_blank" rel="noopener noreferrer">Asenka Guard on GitHub</a>';}
 static function footer_version($text){if(empty($_GET['page'])||sanitize_key(wp_unslash($_GET['page']))!=='asenka-yootheme-image-guard')return $text;return 'Asenka Guard v'.esc_html(self::VERSION);}
 static function definitions(){return [
 'standard_index_placeholder'=>['Directory index placeholder','Small standard index.php file used to discourage directory listing; generally harmless.'],
 'executable_in_writable_area'=>['PHP in uploads','Executable PHP files in uploads can be remotely reachable. Not every occurrence is malicious.'],
 'observed_tmp_php_pattern'=>['Known incident naming pattern','A tmp_ followed by digits and .php in uploads; observed in the October 2026 incident, but a filename alone is not definitive.'],
 'image_polyglot'=>['PHP embedded in image','PHP opening tag detected inside a file with an image extension. Investigate possible image/PHP polyglot.'],
 'php_tag'=>['PHP marker in non-PHP file','A PHP opening tag was found in an image, text or data file.'],
 'execution'=>['Code execution function','The sample contains a PHP execution primitive such as eval, system or shell_exec. These also occur in legitimate software.'],
 'obfuscation'=>['Encoding or decompression','Code includes decoding or decompression functions often used to hide payloads. Legitimate uses exist.'],
 'image_type_mismatch'=>['Image signature mismatch','Declared image extension does not match the actual file header; e.g. a .jpg starting with bzip2 BZh.'],
 'compressed_payload'=>['Compressed content inspected','Bounded decompression succeeded. Findings from the decompressed bytes should be reviewed.'],
 'compressed_uninspected'=>['Compressed content not fully inspected','Decompressor unavailable or file exceeded safe inspection bounds; this is not a clean bill of health.'],
 'jpeg_appended_php'=>['PHP after JPEG image','Recognizable PHP source was found after the JPEG end marker; treat as high-priority evidence.'],
 'jpeg_metadata_php'=>['PHP in JPEG metadata','Recognizable PHP source was found in a JPEG metadata segment rather than compressed pixels.'],
 'image_structure_invalid'=>['Invalid JPEG structure','The full file does not have a valid JPEG end marker or contains malformed marker sections. May be corrupt or truncated.'],
 'embedded_php'=>['Embedded PHP in image','An image-named file contains a PHP marker. Review whether it contains executable code.'],
 'shell_function'=>['Shell execution function','Shell-executing function detected. Common in some tools; investigate in context.'],
 'request_shell_execution'=>['Request + shell function','Request superglobal and shell execution function found in the same source sample.'],
 'request_code_execution'=>['Request + PHP evaluation','Request superglobal and dynamic PHP evaluation found in the same source sample.'],
 'decompression_loader'=>['Decompression loader','PHP source contains a decompression function, potentially paired with a payload file.'],
 'goto_exec_obfuscation'=>['Goto plus dynamic execution','Goto-like obfuscation combined with eval, a high-priority review indicator.'],
 'unusual_root_php'=>['Unexpected root PHP filename','wp-blog.php is not a standard WordPress core entry point. Review content and provenance.'],
 'request_execution'=>['Request-to-execution pattern','Request input appears near code execution, consistent with possible web-shell behavior. Manual verification required.']
 ];}
 static function priority($f){return ($f['state']==='active' && in_array('executable_in_writable_area',(array)$f['signals'],true));}
 static function is_executable($path){return (bool)preg_match('/\.(?:php[34578]?|phtml|phar|pht)$/i',basename($path));}
 static function is_placeholder($f){
  if(strtolower(basename($f['path']))!=='index.php' || intval($f['size'])>512)return false;
  if(!is_file($f['path'])||is_link($f['path'])||!self::allowed($f['path']))return false;
  $raw=@file_get_contents($f['path']);
  return is_string($raw) && (bool)preg_match('~^\s*<\?php\s*(?:(?://|/\*)\s*Silence is golden\.?\s*(?:\*/)?\s*)?(?:\?>)?\s*$~i',$raw);
 }
 static function printable($text){
  $text=preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/',' ',(string)$text);
  if(function_exists('mb_convert_encoding') && !preg_match('//u',$text))$text=mb_convert_encoding($text,'UTF-8','UTF-8');
  elseif(!preg_match('//u',$text))$text=preg_replace('/[\x80-\xFF]/','?', $text);
  return $text;
 }
 static function snippet($f){
  if($f['state']!=='active'||!self::allowed($f['path'])||!is_file($f['path'])||is_link($f['path']))return 'Preview unavailable: file missing or quarantined.';
  $data=@file_get_contents($f['path'],false,null,0,131072);
  if($data===false)return 'Preview unavailable: unable to read file.';
  $needle='/<\?(?:php|=)|\b(?:eval|base64_decode|gzinflate|shell_exec|system|passthru|assert|proc_open)\s*\(/i';
  $ext=strtolower(pathinfo($f['path'],PATHINFO_EXTENSION));$ev=Asenka_Guard_Detector::inspect($data,$ext,$size<=2097152);
  if($ev['decoded_snippet']!=='')return 'Decompressed content (read-only): '.self::printable(substr($ev['decoded_snippet'],0,1200));
  if(preg_match($needle,$data,$m,PREG_OFFSET_CAPTURE)){
   $offset=$m[0][1];return self::printable(substr($data,max(0,$offset-75),550));
  }
  if(strpos($data,"\0")!==false || preg_match('/\.(?:png|jpe?g|gif|webp|avif|bmp|ico)$/i',$f['path']))return 'No suspect PHP code snippet found in the inspected bytes. Binary/image file; use View for metadata.';
  return self::printable(substr($data,0,400))?:'No readable source in this file.';
 }
 static function view(){
  if(!current_user_can('manage_options'))wp_die('Forbidden',403);
  $id=sanitize_text_field(wp_unslash($_GET['id']??''));check_admin_referer('ayig_view_'.$id);
  $items=get_option(self::OPTION,[]);if(!isset($items[$id]))wp_die('Finding unavailable',404);
  $f=$items[$id];$file=$f['state']==='quarantined'?self::store().'/'.$id.'.quarantine':$f['path'];
  if($f['state']==='deleted'||!is_file($file)||is_link($file)||($f['state']==='active'&&!self::allowed($file))||!hash_equals($f['sha256'],hash_file('sha256',$file)))wp_die('File is missing, changed or unsafe to view',409);
  $bytes=@file_get_contents($file,false,null,0,131072);if($bytes===false)wp_die('Unable to read file',500);
  $ev=Asenka_Guard_Detector::inspect($bytes,strtolower(pathinfo($f['path'],PATHINFO_EXTENSION)));$binary=strpos($bytes,"\0")!==false;$imageInfo=@getimagesize($file);
  $mime=is_array($imageInfo)?($imageInfo['mime']??''):'application/octet-stream';
  $displayImage=in_array($mime,['image/png','image/jpeg','image/gif','image/webp'],true) && filesize($file)<=2097152;
  header('Content-Type: text/html; charset=utf-8');header('X-Content-Type-Options: nosniff');header('Cache-Control: no-store, private');header('Content-Security-Policy: default-src \'none\'; img-src data:; style-src \'unsafe-inline\'; sandbox');
  echo '<!doctype html><html><head><meta charset="utf-8"><title>Read-only file viewer</title><style>body{background:#151e25;color:#d8e6eb;font:14px system-ui;padding:24px;line-height:1.5}pre{padding:18px;background:#0b1218;white-space:pre-wrap;overflow-wrap:anywhere;border:1px solid #43515b;color:#e5f0f4}code{color:#8bd8e2}img{max-width:95%;max-height:65vh;border:1px solid #43515b}.hint{color:#abc7d0}</style></head><body><h2>Read-only preview</h2><p><code>'.esc_html($f['path']).'</code></p><p class="hint">Size: '.esc_html(size_format(filesize($file))).' · Modified: '.esc_html(gmdate('Y-m-d H:i:s',filemtime($file))).' UTC · SHA-256: '.esc_html($f['sha256']).'</p>';
  echo '<p class="hint">Detected header: '.esc_html($ev['detected_type']).' · Compressed inspection: '.esc_html($ev['inspection']).'</p>';if($ev['decoded_snippet']!=='')echo '<h3>Decompressed evidence (never executed)</h3><pre>'.esc_html(self::printable(substr($ev['decoded_snippet'],0,8192))).'</pre>';
  if($displayImage){$raw=@file_get_contents($file);if(is_string($raw))echo '<h3>Image preview</h3><img alt="Image content" src="data:'.esc_attr($mime).';base64,'.base64_encode($raw).'">';}
  if($binary){echo '<p class="hint">Binary file. Raw bytes are not displayed as source code.</p>';if(preg_match('/<\?(?:php|=)/i',$bytes,$match,PREG_OFFSET_CAPTURE)){ $offset=$match[0][1];echo '<h3>Embedded PHP marker and surrounding bytes</h3><pre>'.esc_html(self::printable(substr($bytes,max(0,$offset-120),1200))).'</pre>';}else echo '<p>No PHP opening tag found in the first 128 KiB.</p>';}
  else echo '<h3>Source (first 128 KiB, escaped and never executed)</h3><pre>'.esc_html(self::printable($bytes)).'</pre>';
  echo '</body></html>';exit;
 }
 static function action(){if(!current_user_can('manage_options'))wp_die('Forbidden',403);check_admin_referer('ayig');$op=sanitize_key($_POST['operation']??'');$tab=sanitize_key($_POST['tab']??'results');if(!in_array($tab,['dashboard','integrity','results','site','ignored','quarantine','versions','updates'],true))$tab='results';try{if($op==='save_monitor'){self::save_monitor($_POST);$message='Monitoring settings saved.';}elseif($op==='capture_baseline'){self::capture_baseline();$message='Baseline saved after administrator confirmation.';}elseif($op==='scan'){ $scope=$tab==='site'?'site':'uploads';$result=self::scan($scope);$message=ucfirst($scope).' scan complete: '.$result['visited'].' files examined; '.$result['active'].' active findings'.(empty($result['complete'])?' (INCOMPLETE; previous findings retained)':'');}elseif($op==='export')self::csv($tab==='site'?'site':'uploads',true);elseif($op==='export_raw')self::csv($tab==='site'?'site':'uploads',false);elseif($op==='evidence')self::evidence_export(array_map('sanitize_text_field',(array)wp_unslash($_POST['ids']??[])));elseif($op==='ignore'||$op==='unignore'){ $id=sanitize_text_field(wp_unslash($_POST['id']??''));if(!preg_match('/^[a-f0-9]{64}$/D',$id))throw new RuntimeException('Invalid file ID');if($op==='ignore')self::ignore_file($id);else self::unignore_file($id);$message=$op==='ignore'?'File ignored until its contents change.':'Ignore rule removed; scan again to rediscover the file.';}elseif($op==='ignore_bulk'){$ids=array_values(array_unique(array_map('sanitize_text_field',(array)wp_unslash($_POST['ids']??[]))));if(!$ids||count($ids)>200)throw new RuntimeException('Select 1–200 findings');$done=0;foreach($ids as $id){try{self::ignore_file($id);$done++;}catch(Throwable $e){}}$message='Ignored '.$done.' unchanged file(s).';}elseif(in_array($op,['quarantine','restore','delete'],true)){$ids=array_map('sanitize_text_field',(array)wp_unslash($_POST['ids']??[]));if(!$ids && isset($_POST['id']))$ids=[sanitize_text_field(wp_unslash($_POST['id']))];$ids=array_values(array_unique(array_filter($ids)));if(!$ids||count($ids)>200)throw new RuntimeException('Select 1–200 findings');$done=0;$errors=[];foreach($ids as $id){try{self::mutate($id,$op);$done++;}catch(Throwable $e){$errors[]=$id.': '.$e->getMessage();}}$message=ucfirst($op).' completed for '.$done.' file(s)'.($errors?'; errors: '.implode('; ',array_slice($errors,0,3)):'');}else throw new RuntimeException('Invalid operation');}catch(Throwable $e){$message=$e->getMessage();}wp_safe_redirect(add_query_arg(['notice'=>$message],self::admin_url($tab)));exit;}
 static function form($operation,$id='',$label='',$tab='results',$class=''){echo '<form method="post" action="'.esc_url(admin_url('admin-post.php')).'" class="ayig-inline-form">';wp_nonce_field('ayig');echo '<input type="hidden" name="action" value="ayig"><input type="hidden" name="operation" value="'.esc_attr($operation).'"><input type="hidden" name="tab" value="'.esc_attr($tab).'"><input type="hidden" name="id" value="'.esc_attr($id).'"><button class="button ayig-action '.esc_attr($class).'" type="submit" '.($operation==='delete'?'data-confirm="Permanently delete this quarantined file? This cannot be undone."':'').'>'.esc_html($label?:ucfirst($operation)).'</button></form>';}
 static function signal_label($sig){$map=['executable_in_writable_area'=>'PHP in uploads','observed_tmp_php_pattern'=>'tmp PHP','request_shell_execution'=>'request + shell','request_code_execution'=>'request + eval','image_type_mismatch'=>'type mismatch','jpeg_appended_php'=>'JPEG + PHP','jpeg_metadata_php'=>'PHP metadata','image_structure_invalid'=>'JPEG invalid','compressed_uninspected'=>'compressed / unverified','compressed_payload'=>'decompressed','decompression_loader'=>'decoder','goto_exec_obfuscation'=>'goto + eval','standard_index_placeholder'=>'index placeholder'];return $map[$sig]??str_replace('_',' ',$sig);}
 static function signals_ui($f){$definitions=self::definitions();foreach((array)$f['signals'] as $sig){$d=$definitions[$sig]??[$sig,'A scanner heuristic; review the source file.'];$search='https://www.google.com/search?q='.rawurlencode('WordPress security '.$sig);echo '<details class="ayig-signal"><summary>'.esc_html(self::signal_label($sig)).'</summary><div class="ayig-pop"><strong>'.esc_html($d[0]).'</strong><p>'.esc_html($d[1]).'</p><a href="'.esc_url($search).'" target="_blank" rel="noopener noreferrer">Learn more ↗</a></div></details> ';}}
 static function rows($items,$tab){$total=0;foreach($items as $f){if(($tab==='results'||$tab==='site')&&self::scan_scope($f)!==($tab==='site'?'site':'uploads'))continue;if($tab==='quarantine' && $f['state']!=='quarantined')continue;if(($tab==='results'||$tab==='site') && $f['state']!=='active')continue;$total++;$priority=self::priority($f);$id=$f['id'];echo '<tr><td data-label="#" class="ayig-row-number">'.esc_html((string)$total).'</td><td data-label="Select" class="ayig-check-cell"><label><input type="checkbox" class="ayig-select" form="ayig-bulk-form" name="ids[]" value="'.esc_attr($id).'" aria-label="Select '.esc_attr(basename($f['path'])).'"></label></td><td data-label="File path / evidence"><code class="ayig-path '.($priority?'ayig-path-priority':'').'">'.esc_html($f['path']).'</code>';if($priority)echo ' <span class="ayig-alert">Unusual PHP in uploads — review</span>';if(($tab==='results'||$tab==='site') && $f['state']==='active'){ $snippet=self::snippet($f);if($snippet!=='')echo '<details class="ayig-snippet"><summary>Suspect code sample</summary><pre>'.esc_html($snippet).'</pre></details>';}echo '</td><td data-label="Type"><code>'.esc_html(strtoupper(pathinfo($f['path'],PATHINFO_EXTENSION)?:'none')).'</code></td><td data-label="Severity"><span class="ayig-severity ayig-severity-'.esc_attr($f['severity']).'">'.esc_html(strtoupper($f['severity'])).'</span></td><td data-label="Confidence"><span class="ayig-confidence">'.esc_html(ucwords(str_replace('_',' ', $f['confidence']??self::confidence($f['signals'])))).'</span></td><td data-label="Signals">';self::signals_ui($f);echo '</td><td data-label="Last modified">'.esc_html(gmdate('Y-m-d H:i',intval($f['mtime']))).' UTC</td><td data-label="Status">'.esc_html(ucfirst($f['state'])).'</td><td data-label="Actions" class="ayig-actions">';if($f['state']!=='deleted'){ $view=wp_nonce_url(add_query_arg(['action'=>'ayig_view','id'=>$id],admin_url('admin-post.php')),'ayig_view_'.$id);echo '<a class="button ayig-action ayig-view" target="_blank" rel="noopener noreferrer" href="'.esc_url($view).'">◉ View</a>';$download=wp_nonce_url(add_query_arg(['action'=>'ayig_download','id'=>$id],admin_url('admin-post.php')),'ayig_download_'.$id);echo '<a class="button ayig-action ayig-download" href="'.esc_url($download).'" title="Download original bytes as a non-executable .bin file (8 MiB maximum)">↓ Download</a>';}if($f['state']==='active'){if(self::scan_scope($f)==='uploads')self::form('quarantine',$id,'Quarantine',$tab,'ayig-warning');self::form('ignore',$id,'Ignore',$tab,'ayig-ignore');}if($f['state']==='quarantined'){self::form('restore',$id,'↶ Restore',$tab,'ayig-success');self::form('delete',$id,'✕ Delete',$tab,'ayig-danger');}echo '</td></tr>';}if(!$total)echo '<tr class="ayig-empty-row"><td colspan="10">No findings in this view.</td></tr>';}
 /** Informational diagnostic: never attempts to execute a test PHP file. */
 static function security_panel(){
  $d=self::quarantine_diagnostics(false);
  echo '<section class="ayig-security-panel"><h2>Storage &amp; PHP execution diagnostics</h2>';
  echo '<p><strong>Quarantine:</strong> '.esc_html(str_replace('-',' ',ucfirst($d['state']))).' <code>'.esc_html($d['path']).'</code></p>';
  foreach($d['notes'] as $note)echo '<p>'.esc_html($note).'</p>';
  echo '<p><strong>Uploads PHP execution:</strong> Not verified automatically. Examine active Nginx / OpenLiteSpeed / Apache configuration for PHP handling in <code>wp-content/uploads</code>. No executable probe is created.</p>';
  echo '<p>Local filesystem checks cannot prove a path is inaccessible via an HTTP alias. Confirm your server document roots and aliases before relying on quarantine isolation.</p></section>';
 }
 static function page(){if(!current_user_can('manage_options'))return;$tab=sanitize_key(wp_unslash($_GET['tab']??'results'));if(!in_array($tab,['dashboard','integrity','results','site','ignored','quarantine','versions','updates'],true))$tab='results';$items=(array)get_option(self::OPTION,[]);$quarantine=count(array_filter($items,function($f){return $f['state']==='quarantined';}));echo '<div class="wrap ayig-wrap">';if(isset($_GET['notice']))echo '<div class="notice notice-info ayig-notice"><p>'.esc_html(sanitize_text_field(wp_unslash($_GET['notice']))).'</p></div>';echo '<header class="ayig-hero"><div><p class="ayig-kicker">ASENKA SECURITY TOOLKIT</p><div class="ayig-heading" role="heading" aria-level="1"><img class="ayig-header-badge" src="' . esc_url(plugins_url('assets/security-badge.svg',AYIG_FILE)) . '" alt="" width="42" height="42"> Asenka Guard <small>v'.esc_html(self::VERSION).'</small></div><p>Image-handler exposure checks, suspicious-file review and controlled remediation.</p></div></header>';echo '<nav class="ayig-tabs" aria-label="Asenka Guard sections">';foreach(['dashboard'=>'Dashboard','results'=>'Scan Uploads','site'=>'Scan Site','ignored'=>'Ignored Files','quarantine'=>'Quarantine ('.$quarantine.')','versions'=>'YOOtheme Versions','integrity'=>'Integrity','updates'=>'Updates'] as $key=>$label)echo '<a class="'.($tab===$key?'active':'').'" href="'.esc_url(self::admin_url($key)).'">'.esc_html($label).'</a>';echo '</nav>';
 if($tab==='results'||$tab==='site'){$scope=$tab==='site'?'site':'uploads';$last=get_option('ayig_last_scan_'.$scope,$scope==='uploads'?get_option('ayig_last_scan',false):false);if(is_array($last)&&isset($last['at'])){echo '<section class="ayig-scan-summary" aria-label="Last scan summary"><strong>Last scan: '.esc_html(wp_date('M j, Y g:i A',intval($last['at']))).'</strong><span>'.esc_html(number_format_i18n((int)($last['visited']??0))).' files examined</span><span>'.esc_html(number_format_i18n((int)($last['active']??0))).' active findings</span>'.(empty($last['complete'])?'<span class="ayig-summary-warning">Scan incomplete — earlier findings preserved. Check file limits and permissions.</span>':'<span class="ayig-summary-ok">Scan completed</span>').'</section>';}else{echo '<section class="ayig-scan-summary ayig-scan-never" aria-label="Scan status"><strong>Not yet scanned</strong><span>Run a manual scan to check this site. An empty results table does not mean the site is clean.</span></section>';}}
 if($tab==='results'||$tab==='site'){$hist=array_values(array_filter((array)get_option(self::HISTORY,[]),static function($h)use($tab){return ($h['scope']??'uploads')===($tab==='site'?'site':'uploads');}));if($hist){
  $h=end($hist);
  echo '<p class="ayig-history">Last scan changes: <button type="button" class="ayig-change-open" data-change-modal="new" aria-haspopup="dialog">'.esc_html((string)($h['changes']['new']??0)).' new</button> · <button type="button" class="ayig-change-open" data-change-modal="changed" aria-haspopup="dialog">'.esc_html((string)($h['changes']['changed']??0)).' changed</button> · '.esc_html((string)($h['changes']['previously-detected']??0)).' previously detected. Last '.count($hist).' scan summaries retained for this scope.</p>';
  echo '<div class="ayig-change-modal" id="ayig-change-modal" hidden role="dialog" aria-modal="true" aria-labelledby="ayig-change-modal-title"><div class="ayig-change-dialog" role="document"><div class="ayig-change-dialog-top"><h2 id="ayig-change-modal-title">New findings</h2><button type="button" class="ayig-change-close" aria-label="Close findings dialog">&times;</button></div><p class="ayig-change-help">Findings from the latest scan in this section. Files are not modified here.</p><div class="ayig-change-list"></div><div class="ayig-change-footer"><button type="button" class="button ayig-change-close">Close</button></div></div></div>';
  foreach(['new','changed'] as $change){echo '<div class="ayig-change-data" data-change="'.esc_attr($change).'" hidden><ul>';
   foreach($items as $finding){if(self::scan_scope($finding)!==($tab==='site'?'site':'uploads')||($finding['change_status']??'')!==$change||($finding['state']??'')!=='active')continue;
    $id=$finding['id'];$url=wp_nonce_url(add_query_arg(['action'=>'ayig_view','id'=>$id],admin_url('admin-post.php')),'ayig_view_'.$id);
    echo '<li><code>'.esc_html($finding['path']).'</code><span class="ayig-change-meta">'.esc_html(strtoupper((string)($finding['severity']??'review'))).' · '.esc_html(ucwords(str_replace('_',' ',(string)($finding['confidence']??'heuristic')))).'</span><a href="'.esc_url($url).'" target="_blank" rel="noopener noreferrer">View read-only</a></li>';
   }echo '</ul></div>';
  }
 }}
 if($tab==='updates'){Asenka_YOOtheme_Image_Guard_Updater::panel();}
 elseif($tab==='dashboard'){self::dashboard_panel();}
 elseif($tab==='integrity'){self::integrity_panel();}
 elseif($tab==='ignored'){echo '<h2>Ignored files</h2><p>Ignored entries are suppressed only while their SHA-256 hash stays unchanged. Remove an ignore rule and rescan to see the file again.</p><table class="widefat striped ayig-ignored-table"><thead><tr><th>Path</th><th>Scope</th><th>Ignored on</th><th>Action</th></tr></thead><tbody>';foreach(self::ignored() as $id=>$entry){echo '<tr><td><code>'.esc_html($entry['path']).'</code></td><td>'.esc_html($entry['scope']??'uploads').'</td><td>'.esc_html(wp_date('Y-m-d H:i',(int)($entry['ignored_at']??time()))).'</td><td>';self::form('unignore',$id,'Stop ignoring','ignored');echo '</td></tr>';}echo '</tbody></table>'; }
 elseif($tab==='versions'){self::security_panel();echo '<h2>Installed YOOtheme components</h2><table class="widefat striped"><thead><tr><th>Type</th><th>Name</th><th>Version</th><th>Assessment</th></tr></thead><tbody>';foreach(self::versions() as $v)echo '<tr><td>'.esc_html($v['type']).'</td><td>'.esc_html($v['name']).'</td><td>'.esc_html($v['version']).'</td><td>'.esc_html($v['status']).'</td></tr>';echo '</tbody></table><p>Known affected YOOtheme Pro range: 5.0.0–5.0.52. Version detection alone does not establish whether a site was compromised.</p>';}
 else {if($tab==='quarantine')self::security_panel();echo '<div class="ayig-toolbar">';if($tab==='results'||$tab==='site'){if($tab==='site')echo '<p class="ayig-site-warning">Site scan checks files outside uploads and may flag legitimate plugin/theme code. Core/root findings are review-only; do not bulk-quarantine unverified code.</p>';self::form('scan','','⟳ Scan '.($tab==='site'?'Site':'Uploads'),$tab,'ayig-primary');self::form('export','','↓ Export report CSV',$tab);self::form('export_raw','','↓ Findings-only CSV',$tab);echo '<label class="ayig-toggle"><input type="checkbox" id="ayig-highlight" checked> Highlight suspicious PHP paths</label>';}else echo '<p>Quarantined files remain available for read-only viewing, restoration, or permanent deletion.</p>';echo '</div>';echo '<div class="ayig-bulk"><form id="ayig-bulk-form" method="post" action="'.esc_url(admin_url('admin-post.php')).'">';wp_nonce_field('ayig');echo '<input type="hidden" name="action" value="ayig"><input type="hidden" name="tab" value="'.esc_attr($tab).'">';echo '<div class="ayig-bulk-bar"><label><input type="checkbox" class="ayig-select-all"> Select all visible</label> <select name="operation" aria-label="Bulk action">';if($tab==='results'||$tab==='site')echo '<option value="evidence">Download evidence ZIP</option><option value="ignore_bulk">Ignore selected</option>'.($tab==='results'?'<option value="quarantine">Quarantine selected</option>':'');else echo '<option value="restore">Restore selected</option><option value="delete">Permanently delete selected</option>';echo '</select> <button class="button" type="submit">Apply to selected</button> <span class="ayig-count" aria-live="polite">0 selected</span></div>';echo '<div class="ayig-select-by-name"><label for="ayig-name-filter">Select by filename</label><input id="ayig-name-filter" type="text" placeholder=".php, tmp_, .phtml" autocomplete="off"><label><input type="checkbox" id="ayig-match-path"> Match full path</label><button type="button" class="button" id="ayig-select-match">Select matching</button><button type="button" class="button" id="ayig-unselect-match">Unselect matching</button><span id="ayig-matches" aria-live="polite"></span></div>';echo '</form><div class="ayig-filters"><label>Show <select id="ayig-filter-change"><option value="all">All findings</option><option value="new">New only</option><option value="changed">Changed only</option><option value="previously-detected">Previously detected</option></select></label><label>File type <select id="ayig-filter-type"><option value="all">All types</option><option value="php">PHP only</option><option value="image">Images only</option></select></label></div><div class="ayig-table-scroll"><table class="widefat striped ayig-table"><thead><tr><th class="ayig-row-number">#</th><th class="ayig-check-cell"><label><input type="checkbox" class="ayig-select-all" aria-label="Select all findings"></label></th><th>File path / evidence</th><th>Type</th><th>Severity</th><th>Confidence</th><th>Signals</th><th>Last modified</th><th>Status</th><th>Actions</th></tr></thead><tbody>';self::rows($items,$tab);echo '</tbody></table></div>';
 echo '<div class="ayig-bulk-bar ayig-bulk-bar-bottom" aria-label="Bottom bulk actions"><label><input type="checkbox" class="ayig-select-all"> Select all visible</label> <select class="ayig-bottom-operation" aria-label="Bulk action at bottom">';
 if($tab==='results'||$tab==='site')echo '<option value="evidence">Download evidence ZIP</option><option value="ignore_bulk">Ignore selected</option>'.($tab==='results'?'<option value="quarantine">Quarantine selected</option>':'');else echo '<option value="restore">Restore selected</option><option value="delete">Permanently delete selected</option>';
 echo '</select> <button type="submit" form="ayig-bulk-form" class="button">Apply to selected</button> <span class="ayig-count" aria-live="polite">0 selected</span></div><p class="ayig-disclaimer">Scan Uploads examines uploads; Scan Site examines the WordPress installation and limits findings outside uploads to stronger indicators. Site scans can be slower and may reach execution limits. Severity is heuristic; images and PHP files are not automatically malware. A backup and filesystem review are recommended before modifications. Preview content is escaped and limited to 128 KiB.</p>';}
 echo '<footer class="ayig-footer"><span>© '.esc_html(gmdate('Y')).' Asenka Interactive · v'.esc_html(self::VERSION).'</span><a href="https://github.com/Asenka-Dev-Team/Asenka-Guard" target="_blank" rel="noopener noreferrer">GitHub repository ↗</a></footer></div>';}
 static function cli(){WP_CLI::add_command('ayig',new Asenka_YOOtheme_Image_Guard_CLI());}
}
if(defined('WP_CLI') && WP_CLI){class Asenka_YOOtheme_Image_Guard_CLI {function scan($args,$assoc){ $scope=$assoc['scope']??'uploads';$r=Asenka_YOOtheme_Image_Guard::scan($scope);if(empty($r['complete']))WP_CLI::error('Scan incomplete; previous findings preserved. '.$r['visited'].' files visited.');WP_CLI::success(count($r['findings']).' findings; '.$r['visited'].' files visited');}function ignore($args){Asenka_YOOtheme_Image_Guard::ignore_file($args[0]??'');WP_CLI::success('Ignored until modified');}function unignore($args){Asenka_YOOtheme_Image_Guard::unignore_file($args[0]??'');WP_CLI::success('Ignore removed');}function monitor(){Asenka_YOOtheme_Image_Guard::scheduled_scan();WP_CLI::success('Scheduled monitor run invoked (if enabled).');}function integrity(){ $r=Asenka_YOOtheme_Image_Guard::integrity_report();WP_CLI::log($r['state'].': '.count($r['changes']).' changes');}function versions(){WP_CLI\Utils\format_items('table',Asenka_YOOtheme_Image_Guard::versions(),['type','name','version','status']);}function findings($args,$assoc){$items=array_values(get_option(Asenka_YOOtheme_Image_Guard::OPTION,[]));foreach($items as &$f)$f['signals']=implode('|',$f['signals']);WP_CLI\Utils\format_items($assoc['format']??'table',$items,['id','path','severity','confidence','state','signals','sha256']);}function quarantine($args){Asenka_YOOtheme_Image_Guard::mutate($args[0]??'','quarantine');WP_CLI::success('Quarantined');}function restore($args){Asenka_YOOtheme_Image_Guard::mutate($args[0]??'','restore');WP_CLI::success('Restored');}function delete($args,$assoc){if(!isset($assoc['yes']))WP_CLI::error('Requires --yes');Asenka_YOOtheme_Image_Guard::mutate($args[0]??'','delete');WP_CLI::success('Deleted');}}}
