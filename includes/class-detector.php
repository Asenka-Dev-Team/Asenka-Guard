<?php
if (!defined('ABSPATH')) exit;
/** Read-only bounded binary/file heuristics. No execution, shell commands or external fetches. */
final class Asenka_Guard_Detector {
 const LIMIT=2097152; const EXPANDED=4194304;
 static function media($ext){return in_array($ext,['jpg','jpeg','png','gif','webp','avif','bmp','ico'],true);}
 static function type($bytes){
  if(substr($bytes,0,3)==="BZh")return 'bzip2';
  if(substr($bytes,0,2)==="\x1f\x8b")return 'gzip';
  if(substr($bytes,0,3)==="\xff\xd8\xff")return 'jpeg';
  if(substr($bytes,0,8)==="\x89PNG\r\n\x1a\n")return 'png';
  if(in_array(substr($bytes,0,6),['GIF87a','GIF89a'],true))return 'gif';
  if(substr($bytes,0,4)==='RIFF' && substr($bytes,8,4)==='WEBP')return 'webp';
  if(substr($bytes,0,4)==="PK\x03\x04")return 'zip';
  if(substr($bytes,0,5)==='<?php')return 'php';
  if(strlen($bytes)>=2 && ord($bytes[0])===0x78 && in_array(ord($bytes[1]),[0x01,0x9c,0xda],true))return 'zlib';
  return 'unknown';
 }
 static function inspect($bytes,$ext){
  $hits=[];$type=self::type($bytes);$expected=['jpg'=>'jpeg','jpeg'=>'jpeg','png'=>'png','gif'=>'gif','webp'=>'webp'];
  if(self::media($ext) && isset($expected[$ext]) && $type!==$expected[$ext])$hits[]='image_type_mismatch';
  $data=$bytes;$decoded=null;$inspection='not-needed';
  if(in_array($type,['bzip2','gzip','zlib'],true)){
   $inspection='unavailable';
   if(strlen($bytes)<=262144){
    if($type==='bzip2' && function_exists('bzdecompress'))$decoded=@bzdecompress($bytes);
    elseif($type==='gzip' && function_exists('gzdecode'))$decoded=@gzdecode($bytes,self::EXPANDED);
    elseif($type==='zlib' && function_exists('gzuncompress'))$decoded=@gzuncompress($bytes,self::EXPANDED);
    if(is_string($decoded) && strlen($decoded)<=self::EXPANDED){$inspection='inspected';$hits[]='compressed_payload';$data=$decoded;}else{$decoded='';}
   }
   if($inspection==='unavailable')$hits[]='compressed_uninspected';
  }
  if(self::media($ext) && preg_match('/<\?(?:php|=)/i',$data))$hits[]='embedded_php';
  if(preg_match('/\b(?:shell_exec|system|passthru|proc_open|popen|exec)\s*\(/i',$data))$hits[]='shell_function';
  if(preg_match('/\b(?:bzdecompress|gzdecode|gzuncompress|gzinflate)\s*\(/i',$data))$hits[]='decompression_loader';
  if(preg_match('/\b(?:eval|assert)\s*\(/i',$data) && preg_match('/\$_(?:POST|GET|REQUEST|COOKIE)\b/i',$data))$hits[]='request_code_execution';
  if(preg_match('/\b(?:shell_exec|system|passthru|proc_open|popen|exec)\s*\(/i',$data) && preg_match('/\$_(?:POST|GET|REQUEST|COOKIE)\b/i',$data))$hits[]='request_shell_execution';
  if(preg_match('/\bgoto\s+[a-zA-Z_][a-zA-Z_0-9]*\s*;/i',$data) && preg_match('/\beval\s*\(/i',$data))$hits[]='goto_exec_obfuscation';
  return ['signals'=>array_values(array_unique($hits)),'detected_type'=>$type,'inspection'=>$inspection,'decoded_snippet'=>is_string($decoded)&&$decoded!==''?substr($decoded,0,131072):''];
 }
}
