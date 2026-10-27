<?php
if (!defined('ABSPATH')) exit;
final class Asenka_YOOtheme_Image_Guard {
 const VERSION=AYIG_VERSION; const OPTION='ayig_findings'; const LOG='ayig_audit'; const IGNORED='ayig_ignored_files';
 static function init(){add_action('admin_menu',[__CLASS__,'menu']);add_action('admin_post_ayig',[__CLASS__,'action']);add_action('admin_post_ayig_view',[__CLASS__,'view']);add_action('admin_enqueue_scripts',[__CLASS__,'assets']);add_filter('admin_footer_text',[__CLASS__,'footer']);add_filter('update_footer',[__CLASS__,'footer_version'],20); if(defined('WP_CLI') && WP_CLI) self::cli();}
 static function menu(){
  add_management_page('Asenka Guard','Asenka Guard','manage_options','asenka-yootheme-image-guard',[__CLASS__,'page']);
  // Give Image Guard its own recognizable security icon in the main WP admin sidebar.
  $svg='<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 64 64"><path d="M32 5 54 13v16c0 16-9 25-22 31C19 54 10 45 10 29V13L32 5Z" fill="none" stroke="#a7aaad" stroke-width="5"/><path d="m22 32 7 7 14-16" fill="none" stroke="#a7aaad" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  add_menu_page('Asenka Guard','Asenka Guard','manage_options','asenka-yootheme-image-guard',[__CLASS__,'page'],'data:image/svg+xml;base64,'.base64_encode($svg),81);
 }
 static function roots($scope='uploads'){return $scope==='site'?[ABSPATH]:[WP_CONTENT_DIR.'/uploads'];}
 static function scan_scope($f){return ($f['scope']??'uploads')==='site'?'site':'uploads';}
 static function ignored(){return (array)get_option(self::IGNORED,[]);}
 static function versions(){ $out=[]; foreach(wp_get_themes() as $slug=>$theme){if(stripos($slug,'yootheme')!==false || stripos($theme->get('Name'),'yootheme')!==false){$v=$theme->get('Version');$out[]=['type'=>'theme','name'=>$theme->get('Name'),'version'=>$v,'status'=>self::status($v)];}} foreach(get_plugins() as $path=>$plugin){if(stripos($path,'yootheme')!==false || stripos($plugin['Name'],'yootheme')!==false){$v=$plugin['Version'];$out[]=['type'=>'plugin','name'=>$plugin['Name'],'version'=>$v,'status'=>self::status($v)];}}return $out; }
 static function status($v){if(!preg_match('/^\d+\.\d+\.\d+/',$v))return 'unknown';return version_compare($v,'5.0.0','>=') && version_compare($v,'5.0.53','<')?'VULNERABLE':'not in known affected range';}
 static function signatures($data,$extension){$hits=[]; $rules=['php_tag'=>'/<\?(?:php|=)/i','execution'=>'/\b(?:eval|assert|shell_exec|passthru|system|proc_open|popen)\s*\(/i','obfuscation'=>'/\b(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(/i','request_execution'=>'/(?:\$_(?:POST|GET|REQUEST|COOKIE)\s*\[.{0,100}\]).{0,200}(?:eval|system|shell_exec)|(?:eval|system|shell_exec)\s*\(.{0,150}\$_(?:POST|GET|REQUEST|COOKIE)/is','image_polyglot'=>'/<\?(?:php|=)/i'];foreach($rules as $id=>$re){if($id==='image_polyglot' && !in_array($extension,['png','jpg','jpeg','gif','webp','avif','bmp','ico'],true))continue;if($id==='php_tag' && !in_array($extension,['png','jpg','jpeg','gif','webp','avif','bmp','ico','svg','txt','dat'],true))continue;if(preg_match($re,$data))$hits[]=$id;}return $hits;}
 /** Scans uploads or WordPress installation. A site scan does not follow symlinks. */
 static function scan($scope='uploads'){
  if(!in_array($scope,['uploads','site'],true))throw new RuntimeException('Invalid scan scope');
  $findings=[];$count=0;$limit=150000;$truncated=false;$ignored=self::ignored();
  foreach(self::roots($scope) as $root){
   if(!is_dir($root))continue;
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
    if($scope==='site'&&!$executable&&!in_array($ext,['png','jpg','jpeg','gif','webp','avif','svg','ico','pht','phtml'],true))continue;
    $data=$size<=2097152?@file_get_contents($path):@file_get_contents($path,false,null,0,131072);
    if($data===false)continue;
    $hits=self::signatures($data,$ext);
    if($executable&&$inUploads)$hits[]='executable_in_writable_area';
    if($executable&&$inUploads&&preg_match('~^tmp_[0-9]+\.php$~i',basename($path)))$hits[]='observed_tmp_php_pattern';
    if(!$hits)continue;
    if($executable&&strtolower(basename($path))==='index.php'&&$size<=512&&preg_match('~^\s*<\?php\s*(?:(?://|/\*)\s*Silence is golden\.?\s*(?:\*/)?\s*)?(?:\?>)?\s*$~i',$data))$hits=['standard_index_placeholder'];
    // PHP in core, themes and plugins is ordinary. Only retain stronger code indicators there.
    if($scope==='site'&&!$inUploads && !in_array('request_execution',$hits,true) && !(in_array('execution',$hits,true)&&in_array('obfuscation',$hits,true)) && !in_array('image_polyglot',$hits,true))continue;
    $id=hash('sha256',$real);$sha=@hash_file('sha256',$real);if(!$sha)continue;
    if(isset($ignored[$id]) && hash_equals((string)$ignored[$id]['sha256'],$sha))continue;
    if(isset($ignored[$id]))unset($ignored[$id]); // Any file modification revokes its ignore rule.
    $findings[$id]=['id'=>$id,'path'=>$real,'size'=>$size,'mtime'=>$file->getMTime(),'sha256'=>$sha,'permissions'=>substr(sprintf('%o',$file->getPerms()),-4),'confidence'=>self::confidence($hits),'signals'=>array_values(array_unique($hits)),'severity'=>self::classify($hits,$executable),'state'=>'active','scope'=>$scope];
   }
  }
  $previous=(array)get_option(self::OPTION,[]);
  foreach($previous as $old_id=>$old){
   if(($old['state']??'active')==='quarantined'||($old['state']??'active')==='deleted')$findings[$old_id]=$old;
   elseif(self::scan_scope($old)!==$scope && ($old['state']??'active')==='active')$findings[$old_id]=$old;
  }
  update_option(self::IGNORED,$ignored,false);
  update_option(self::OPTION,$findings,false);
  $active=count(array_filter($findings,static function($f)use($scope){return ($f['state']??'')==='active' && self::scan_scope($f)===$scope;}));
  update_option('ayig_last_scan_'.$scope,['at'=>time(),'visited'=>$count,'active'=>$active,'truncated'=>$truncated],false);
  if($scope==='uploads')update_option('ayig_last_scan',['at'=>time(),'visited'=>$count,'active'=>$active,'truncated'=>$truncated],false);
  self::audit('scan_'.$scope,$active.' active findings; '.$count.' files visited');
  return ['findings'=>$findings,'visited'=>$count,'truncated'=>$truncated,'active'=>$active];
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
  $request=in_array('request_execution',$hits,true);
  $exec=in_array('execution',$hits,true);
  $obfuscated=in_array('obfuscation',$hits,true);
  $polyglot=in_array('image_polyglot',$hits,true);
  $tmp=in_array('observed_tmp_php_pattern',$hits,true);
  if($request && ($exec || $obfuscated || $polyglot))return 'critical';
  if($request || ($exec && $obfuscated) || ($tmp && ($exec || $obfuscated)))return 'high';
  if($tmp || ($polyglot && ($exec || $obfuscated)))return 'high';
  if($executable || $polyglot || $exec || $obfuscated)return 'review';
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
  if(in_array('observed_tmp_php_pattern',$signals,true)||in_array('image_polyglot',$signals,true))return 'suspicious';
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
   if($f['state']!=='active')throw new RuntimeException('Not active');
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
 static function csv(){ $items=get_option(self::OPTION,[]);header('Content-Type: text/csv; charset=utf-8');header('Content-Disposition: attachment; filename="asenka-yootheme-image-guard-findings-'.gmdate('Ymd-His').'.csv"');header('X-Content-Type-Options: nosniff');$o=fopen('php://output','w');fputcsv($o,['Path','Severity','Confidence','State','Signals','Size','Modified UTC','SHA256','Permissions']);foreach($items as $f){$path=$f['path'];if(preg_match('/^[=+@\-\t\r]/',$path))$path="'".$path;fputcsv($o,[$path,$f['severity'],$f['confidence']??self::confidence($f['signals']),$f['state'],implode('|',$f['signals']),$f['size'],gmdate('c',$f['mtime']),$f['sha256'],$f['permissions']??'']);}fclose($o);exit;}
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
  $binary=strpos($bytes,"\0")!==false;$imageInfo=@getimagesize($file);
  $mime=is_array($imageInfo)?($imageInfo['mime']??''):'application/octet-stream';
  $displayImage=in_array($mime,['image/png','image/jpeg','image/gif','image/webp'],true) && filesize($file)<=2097152;
  header('Content-Type: text/html; charset=utf-8');header('X-Content-Type-Options: nosniff');header('Cache-Control: no-store, private');header('Content-Security-Policy: default-src \'none\'; img-src data:; style-src \'unsafe-inline\'; sandbox');
  echo '<!doctype html><html><head><meta charset="utf-8"><title>Read-only file viewer</title><style>body{background:#151e25;color:#d8e6eb;font:14px system-ui;padding:24px;line-height:1.5}pre{padding:18px;background:#0b1218;white-space:pre-wrap;overflow-wrap:anywhere;border:1px solid #43515b;color:#e5f0f4}code{color:#8bd8e2}img{max-width:95%;max-height:65vh;border:1px solid #43515b}.hint{color:#abc7d0}</style></head><body><h2>Read-only preview</h2><p><code>'.esc_html($f['path']).'</code></p><p class="hint">Size: '.esc_html(size_format(filesize($file))).' · Modified: '.esc_html(gmdate('Y-m-d H:i:s',filemtime($file))).' UTC · SHA-256: '.esc_html($f['sha256']).'</p>';
  if($displayImage){$raw=@file_get_contents($file);if(is_string($raw))echo '<h3>Image preview</h3><img alt="Image content" src="data:'.esc_attr($mime).';base64,'.base64_encode($raw).'">';}
  if($binary){echo '<p class="hint">Binary file. Raw bytes are not displayed as source code.</p>';if(preg_match('/<\?(?:php|=)/i',$bytes,$match,PREG_OFFSET_CAPTURE)){ $offset=$match[0][1];echo '<h3>Embedded PHP marker and surrounding bytes</h3><pre>'.esc_html(self::printable(substr($bytes,max(0,$offset-120),1200))).'</pre>';}else echo '<p>No PHP opening tag found in the first 128 KiB.</p>';}
  else echo '<h3>Source (first 128 KiB, escaped and never executed)</h3><pre>'.esc_html(self::printable($bytes)).'</pre>';
  echo '</body></html>';exit;
 }
 static function action(){if(!current_user_can('manage_options'))wp_die('Forbidden',403);check_admin_referer('ayig');$op=sanitize_key($_POST['operation']??'');$tab=sanitize_key($_POST['tab']??'results');if(!in_array($tab,['results','site','ignored','quarantine','versions','updates'],true))$tab='results';try{if($op==='scan'){ $scope=$tab==='site'?'site':'uploads';$result=self::scan($scope);$message=ucfirst($scope).' scan complete: '.$result['visited'].' files examined; '.$result['active'].' active findings'.($result['truncated']?' (limit reached)':'');}elseif($op==='export')self::csv();elseif($op==='ignore'||$op==='unignore'){ $id=sanitize_text_field(wp_unslash($_POST['id']??''));if(!preg_match('/^[a-f0-9]{64}$/D',$id))throw new RuntimeException('Invalid file ID');if($op==='ignore')self::ignore_file($id);else self::unignore_file($id);$message=$op==='ignore'?'File ignored until its contents change.':'Ignore rule removed; scan again to rediscover the file.';}elseif(in_array($op,['quarantine','restore','delete'],true)){$ids=array_map('sanitize_text_field',(array)wp_unslash($_POST['ids']??[]));if(!$ids && isset($_POST['id']))$ids=[sanitize_text_field(wp_unslash($_POST['id']))];$ids=array_values(array_unique(array_filter($ids)));if(!$ids||count($ids)>200)throw new RuntimeException('Select 1–200 findings');$done=0;$errors=[];foreach($ids as $id){try{self::mutate($id,$op);$done++;}catch(Throwable $e){$errors[]=$id.': '.$e->getMessage();}}$message=ucfirst($op).' completed for '.$done.' file(s)'.($errors?'; errors: '.implode('; ',array_slice($errors,0,3)):'');}else throw new RuntimeException('Invalid operation');}catch(Throwable $e){$message=$e->getMessage();}wp_safe_redirect(add_query_arg(['notice'=>$message],self::admin_url($tab)));exit;}
 static function form($operation,$id='',$label='',$tab='results',$class=''){echo '<form method="post" action="'.esc_url(admin_url('admin-post.php')).'" class="ayig-inline-form">';wp_nonce_field('ayig');echo '<input type="hidden" name="action" value="ayig"><input type="hidden" name="operation" value="'.esc_attr($operation).'"><input type="hidden" name="tab" value="'.esc_attr($tab).'"><input type="hidden" name="id" value="'.esc_attr($id).'"><button class="button ayig-action '.esc_attr($class).'" type="submit" '.($operation==='delete'?'data-confirm="Permanently delete this quarantined file? This cannot be undone."':'').'>'.esc_html($label?:ucfirst($operation)).'</button></form>';}
 static function signals_ui($f){$definitions=self::definitions();foreach((array)$f['signals'] as $sig){$d=$definitions[$sig]??[$sig,'A scanner heuristic; review the source file.'];$search='https://www.google.com/search?q='.rawurlencode('WordPress security '.$sig);echo '<details class="ayig-signal"><summary>'.esc_html(str_replace('_',' ',$sig)).'</summary><div class="ayig-pop"><strong>'.esc_html($d[0]).'</strong><p>'.esc_html($d[1]).'</p><a href="'.esc_url($search).'" target="_blank" rel="noopener noreferrer">Learn more ↗</a></div></details> ';}}
 static function rows($items,$tab){$total=0;foreach($items as $f){if(($tab==='results'||$tab==='site')&&self::scan_scope($f)!==($tab==='site'?'site':'uploads'))continue;if($tab==='quarantine' && $f['state']!=='quarantined')continue;if(($tab==='results'||$tab==='site') && $f['state']!=='active')continue;$total++;$priority=self::priority($f);$id=$f['id'];echo '<tr><td data-label="#" class="ayig-row-number">'.esc_html((string)$total).'</td><td data-label="Select" class="ayig-check-cell"><label><input type="checkbox" class="ayig-select" form="ayig-bulk-form" name="ids[]" value="'.esc_attr($id).'" aria-label="Select '.esc_attr(basename($f['path'])).'"></label></td><td data-label="File path / evidence"><code class="ayig-path '.($priority?'ayig-path-priority':'').'">'.esc_html($f['path']).'</code>';if($priority)echo ' <span class="ayig-alert">Unusual PHP in uploads — review</span>';if(($tab==='results'||$tab==='site') && $f['state']==='active'){ $snippet=self::snippet($f);if($snippet!=='')echo '<details class="ayig-snippet"><summary>Suspect code sample</summary><pre>'.esc_html($snippet).'</pre></details>';}echo '</td><td data-label="Type"><code>'.esc_html(strtoupper(pathinfo($f['path'],PATHINFO_EXTENSION)?:'none')).'</code></td><td data-label="Severity"><span class="ayig-severity ayig-severity-'.esc_attr($f['severity']).'">'.esc_html(strtoupper($f['severity'])).'</span></td><td data-label="Confidence"><span class="ayig-confidence">'.esc_html(ucwords(str_replace('_',' ', $f['confidence']??self::confidence($f['signals'])))).'</span></td><td data-label="Signals">';self::signals_ui($f);echo '</td><td data-label="Last modified">'.esc_html(gmdate('Y-m-d H:i',intval($f['mtime']))).' UTC</td><td data-label="Status">'.esc_html(ucfirst($f['state'])).'</td><td data-label="Actions" class="ayig-actions">';if($f['state']!=='deleted'){ $view=wp_nonce_url(add_query_arg(['action'=>'ayig_view','id'=>$id],admin_url('admin-post.php')),'ayig_view_'.$id);echo '<a class="button ayig-action ayig-view" target="_blank" rel="noopener noreferrer" href="'.esc_url($view).'">◉ View</a>';}if($f['state']==='active'){if(self::scan_scope($f)==='uploads'||self::within($f['path'],WP_CONTENT_DIR))self::form('quarantine',$id,'▣ Quarantine',$tab,'ayig-warning');self::form('ignore',$id,'Ignore file',$tab,'ayig-ignore');}if($f['state']==='quarantined'){self::form('restore',$id,'↶ Restore',$tab,'ayig-success');self::form('delete',$id,'✕ Delete',$tab,'ayig-danger');}echo '</td></tr>';}if(!$total)echo '<tr class="ayig-empty-row"><td colspan="10">No findings in this view.</td></tr>';}
 /** Informational diagnostic: never attempts to execute a test PHP file. */
 static function security_panel(){
  $d=self::quarantine_diagnostics(false);
  echo '<section class="ayig-security-panel"><h2>Storage &amp; PHP execution diagnostics</h2>';
  echo '<p><strong>Quarantine:</strong> '.esc_html(str_replace('-',' ',ucfirst($d['state']))).' <code>'.esc_html($d['path']).'</code></p>';
  foreach($d['notes'] as $note)echo '<p>'.esc_html($note).'</p>';
  echo '<p><strong>Uploads PHP execution:</strong> Not verified automatically. Examine active Nginx / OpenLiteSpeed / Apache configuration for PHP handling in <code>wp-content/uploads</code>. No executable probe is created.</p>';
  echo '<p>Local filesystem checks cannot prove a path is inaccessible via an HTTP alias. Confirm your server document roots and aliases before relying on quarantine isolation.</p></section>';
 }
 static function page(){if(!current_user_can('manage_options'))return;$tab=sanitize_key(wp_unslash($_GET['tab']??'results'));if(!in_array($tab,['results','site','ignored','quarantine','versions','updates'],true))$tab='results';$items=(array)get_option(self::OPTION,[]);$quarantine=count(array_filter($items,function($f){return $f['state']==='quarantined';}));echo '<div class="wrap ayig-wrap">';if(isset($_GET['notice']))echo '<div class="notice notice-info ayig-notice"><p>'.esc_html(sanitize_text_field(wp_unslash($_GET['notice']))).'</p></div>';echo '<header class="ayig-hero"><div><p class="ayig-kicker">ASENKA SECURITY TOOLKIT</p><div class="ayig-heading" role="heading" aria-level="1"><img class="ayig-header-badge" src="' . esc_url(plugins_url('assets/security-badge.svg',AYIG_FILE)) . '" alt="" width="42" height="42"> Asenka Guard <small>v'.esc_html(self::VERSION).'</small></div><p>Image-handler exposure checks, suspicious-file review and controlled remediation.</p></div></header>';echo '<nav class="ayig-tabs" aria-label="Asenka Guard sections">';foreach(['results'=>'Scan Uploads','site'=>'Scan Site','ignored'=>'Ignored Files','quarantine'=>'Quarantine ('.$quarantine.')','versions'=>'YOOtheme Versions','updates'=>'Updates'] as $key=>$label)echo '<a class="'.($tab===$key?'active':'').'" href="'.esc_url(self::admin_url($key)).'">'.esc_html($label).'</a>';echo '</nav>';
 if($tab==='results'||$tab==='site'){$scope=$tab==='site'?'site':'uploads';$last=get_option('ayig_last_scan_'.$scope,$scope==='uploads'?get_option('ayig_last_scan',false):false);if(is_array($last)&&isset($last['at'])){echo '<section class="ayig-scan-summary" aria-label="Last scan summary"><strong>Last scan: '.esc_html(wp_date('M j, Y g:i A',intval($last['at']))).'</strong><span>'.esc_html(number_format_i18n((int)($last['visited']??0))).' files examined</span><span>'.esc_html(number_format_i18n((int)($last['active']??0))).' active findings</span>'.(!empty($last['truncated'])?'<span class="ayig-summary-warning">Scan limit reached — results may be incomplete</span>':'<span class="ayig-summary-ok">Scan completed within file limit</span>').'</section>';}else{echo '<section class="ayig-scan-summary ayig-scan-never" aria-label="Scan status"><strong>Not yet scanned</strong><span>Run a manual scan to check this site. An empty results table does not mean the site is clean.</span></section>';}}
 if($tab==='updates'){Asenka_YOOtheme_Image_Guard_Updater::panel();}
 elseif($tab==='ignored'){echo '<h2>Ignored files</h2><p>Ignored entries are suppressed only while their SHA-256 hash stays unchanged. Remove an ignore rule and rescan to see the file again.</p><table class="widefat striped ayig-ignored-table"><thead><tr><th>Path</th><th>Scope</th><th>Ignored on</th><th>Action</th></tr></thead><tbody>';foreach(self::ignored() as $id=>$entry){echo '<tr><td><code>'.esc_html($entry['path']).'</code></td><td>'.esc_html($entry['scope']??'uploads').'</td><td>'.esc_html(wp_date('Y-m-d H:i',(int)($entry['ignored_at']??time()))).'</td><td>';self::form('unignore',$id,'Stop ignoring','ignored');echo '</td></tr>';}echo '</tbody></table>'; }
 elseif($tab==='versions'){self::security_panel();echo '<h2>Installed YOOtheme components</h2><table class="widefat striped"><thead><tr><th>Type</th><th>Name</th><th>Version</th><th>Assessment</th></tr></thead><tbody>';foreach(self::versions() as $v)echo '<tr><td>'.esc_html($v['type']).'</td><td>'.esc_html($v['name']).'</td><td>'.esc_html($v['version']).'</td><td>'.esc_html($v['status']).'</td></tr>';echo '</tbody></table><p>Known affected YOOtheme Pro range: 5.0.0–5.0.52. Version detection alone does not establish whether a site was compromised.</p>';}
 else {if($tab==='quarantine')self::security_panel();echo '<div class="ayig-toolbar">';if($tab==='results'||$tab==='site'){if($tab==='site')echo '<p class="ayig-site-warning">Site scan checks files outside uploads and may flag legitimate plugin/theme code. Core/root findings are review-only; do not bulk-quarantine unverified code.</p>';self::form('scan','','⟳ Scan '.($tab==='site'?'Site':'Uploads'),$tab,'ayig-primary');self::form('export','','↓ Export CSV',$tab);echo '<label class="ayig-toggle"><input type="checkbox" id="ayig-highlight" checked> Highlight suspicious PHP paths</label>';}else echo '<p>Quarantined files remain available for read-only viewing, restoration, or permanent deletion.</p>';echo '</div>';echo '<div class="ayig-bulk"><form id="ayig-bulk-form" method="post" action="'.esc_url(admin_url('admin-post.php')).'">';wp_nonce_field('ayig');echo '<input type="hidden" name="action" value="ayig"><input type="hidden" name="tab" value="'.esc_attr($tab).'">';echo '<div class="ayig-bulk-bar"><label><input type="checkbox" class="ayig-select-all"> Select all visible</label> <select name="operation" aria-label="Bulk action">';if($tab==='results'||$tab==='site')echo '<option value="quarantine">Quarantine selected</option>';else echo '<option value="restore">Restore selected</option><option value="delete">Permanently delete selected</option>';echo '</select> <button class="button" type="submit">Apply to selected</button> <span class="ayig-count" aria-live="polite">0 selected</span></div>';echo '<div class="ayig-select-by-name"><label for="ayig-name-filter">Select by filename</label><input id="ayig-name-filter" type="text" placeholder=".php, tmp_, .phtml" autocomplete="off"><label><input type="checkbox" id="ayig-match-path"> Match full path</label><button type="button" class="button" id="ayig-select-match">Select matching</button><button type="button" class="button" id="ayig-unselect-match">Unselect matching</button><span id="ayig-matches" aria-live="polite"></span></div>';echo '</form><div class="ayig-table-scroll"><table class="widefat striped ayig-table"><thead><tr><th class="ayig-row-number">#</th><th class="ayig-check-cell"><label><input type="checkbox" class="ayig-select-all" aria-label="Select all findings"></label></th><th>File path / evidence</th><th>Type</th><th>Severity</th><th>Confidence</th><th>Signals</th><th>Last modified</th><th>Status</th><th>Actions</th></tr></thead><tbody>';self::rows($items,$tab);echo '</tbody></table></div>';
 echo '<div class="ayig-bulk-bar ayig-bulk-bar-bottom" aria-label="Bottom bulk actions"><label><input type="checkbox" class="ayig-select-all"> Select all visible</label> <select class="ayig-bottom-operation" aria-label="Bulk action at bottom">';
 if($tab==='results'||$tab==='site')echo '<option value="quarantine">Quarantine selected</option>';else echo '<option value="restore">Restore selected</option><option value="delete">Permanently delete selected</option>';
 echo '</select> <button type="submit" form="ayig-bulk-form" class="button">Apply to selected</button> <span class="ayig-count" aria-live="polite">0 selected</span></div><p class="ayig-disclaimer">Scan Uploads examines uploads; Scan Site examines the WordPress installation and limits findings outside uploads to stronger indicators. Site scans can be slower and may reach execution limits. Severity is heuristic; images and PHP files are not automatically malware. A backup and filesystem review are recommended before modifications. Preview content is escaped and limited to 128 KiB.</p>';}
 echo '<footer class="ayig-footer"><span>© '.esc_html(gmdate('Y')).' Asenka Interactive · v'.esc_html(self::VERSION).'</span><a href="https://github.com/Asenka-Dev-Team/Asenka-Guard" target="_blank" rel="noopener noreferrer">GitHub repository ↗</a></footer></div>';}
 static function cli(){WP_CLI::add_command('ayig',new Asenka_YOOtheme_Image_Guard_CLI());}
}
if(defined('WP_CLI') && WP_CLI){class Asenka_YOOtheme_Image_Guard_CLI {function scan($args,$assoc){ $scope=$assoc['scope']??'uploads';$r=Asenka_YOOtheme_Image_Guard::scan($scope);WP_CLI::success(count($r['findings']).' findings; '.$r['visited'].' files visited'.($r['truncated']?' (LIMIT REACHED)':''));}function ignore($args){Asenka_YOOtheme_Image_Guard::ignore_file($args[0]??'');WP_CLI::success('Ignored until modified');}function unignore($args){Asenka_YOOtheme_Image_Guard::unignore_file($args[0]??'');WP_CLI::success('Ignore removed');}function versions(){WP_CLI\Utils\format_items('table',Asenka_YOOtheme_Image_Guard::versions(),['type','name','version','status']);}function findings($args,$assoc){$items=array_values(get_option(Asenka_YOOtheme_Image_Guard::OPTION,[]));foreach($items as &$f)$f['signals']=implode('|',$f['signals']);WP_CLI\Utils\format_items($assoc['format']??'table',$items,['id','path','severity','confidence','state','signals','sha256']);}function quarantine($args){Asenka_YOOtheme_Image_Guard::mutate($args[0]??'','quarantine');WP_CLI::success('Quarantined');}function restore($args){Asenka_YOOtheme_Image_Guard::mutate($args[0]??'','restore');WP_CLI::success('Restored');}function delete($args,$assoc){if(!isset($assoc['yes']))WP_CLI::error('Requires --yes');Asenka_YOOtheme_Image_Guard::mutate($args[0]??'','delete');WP_CLI::success('Deleted');}}}
