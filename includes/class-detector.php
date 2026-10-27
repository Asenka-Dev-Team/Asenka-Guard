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
 /** Parse JPEG segments without interpreting compressed pixel data as PHP code. */
 static function jpeg_parts($bytes){
  $length=strlen($bytes);$bad=['valid'=>false,'end'=>false,'metadata'=>'','tail'=>''];
  if($length<4||substr($bytes,0,2)!=="\xff\xd8")return $bad;
  $i=2;$entropy=false;$meta='';$segments=0;
  while($i<$length-1 && ++$segments<200000){
   if(ord($bytes[$i])!==255){if($entropy){$i++;continue;}return $bad;}
   while($i<$length && ord($bytes[$i])===255)$i++;
   if($i >= $length)return $bad;
   $marker=ord($bytes[$i++]);
   if($marker===0){if(!$entropy)return $bad;continue;}
   if($marker===0xd9)return ['valid'=>true,'end'=>$i,'metadata'=>$meta,'tail'=>substr($bytes,$i)];
   if($marker===0xd8 || $marker===0x01 || ($marker>=0xd0 && $marker<=0xd7))continue;
   if($i+2>$length)return $bad;
   $size=(ord($bytes[$i])<<8)|ord($bytes[$i+1]);
   if($size<2 || $i+$size>$length)return $bad;
   // APP0–APP15 and COM data are non-image entropy: investigate credible code there.
   if(($marker>=0xe0&&$marker<=0xef)||$marker===0xfe){
    $piece=substr($bytes,$i+2,$size-2);
    if(strlen($meta)+strlen($piece)<=self::LIMIT)$meta.=$piece;
   }
   $i+=$size;
   if($marker===0xda)$entropy=true;
  }
  return $bad;
 }
 static function jpeg_end($bytes){$part=self::jpeg_parts($bytes);return $part['end'];}
 static function png_end($bytes){
  $length=strlen($bytes);if(substr($bytes,0,8)!=="\x89PNG\r\n\x1a\n")return false;
  $i=8;
  while($i+12<=$length){
   $n=unpack('N',substr($bytes,$i,4))[1];
   if($n>self::LIMIT || $i+12+$n>$length)return false;
   $name=substr($bytes,$i+4,4);$i+=12+$n;
   if($name==='IEND')return $i;
  }
  return false;
 }
 /** Require an actual PHP program structure, rather than an accidental JPEG byte pair. */
 static function php_payload($data){
  if(!preg_match('/<\?(?:php|=)/i',$data))return false;
  // Opening tag and recognizable dangerous execution are considerably stronger
  // evidence than a marker alone. Never execute the candidate source.
  $hasExec=preg_match('/\b(?:eval|assert|shell_exec|system|passthru|proc_open|popen|base64_decode|gzinflate|bzdecompress)\s*\(/i',$data);
  $hasStatement=preg_match('/<\?php\s+(?:[$a-z_]|\/\*|\/\/)/i',$data);
  $hasRequest=preg_match('/\$_(?:POST|GET|REQUEST|COOKIE)\s*\[/i',$data);
  $hasSource=preg_match('/<\?php\s+(?:echo|print|include|require|function|class|if|\$[a-z_][a-z_0-9]*\s*=)/i',$data) || preg_match('/<\?=\s*\$[a-z_][a-z_0-9]*/i',$data);
  return (bool)(($hasExec && ($hasRequest || $hasStatement)) || ($hasRequest && $hasStatement) || $hasSource);
 }
 static function inspect($bytes,$ext,$completeFile=true){
  $hits=[];$type=self::type($bytes);$expected=['jpg'=>'jpeg','jpeg'=>'jpeg','png'=>'png','gif'=>'gif','webp'=>'webp'];
  if(self::media($ext) && isset($expected[$ext]) && $type!==$expected[$ext])$hits[]='image_type_mismatch';
  $data=$bytes;$decoded=null;$inspection='not-needed';$codeData='';
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
  if(self::media($ext) && $type==='jpeg'){
   $parts=self::jpeg_parts($bytes);
   if($parts['valid']){
    // Compressed scan data is opaque. Accidental <? and <?= tokens there are ignored.
    if(self::php_payload($parts['tail'])){$hits[]='jpeg_appended_php';$hits[]='embedded_php';$codeData=$parts['tail'];}
    if(self::php_payload($parts['metadata'])){$hits[]='jpeg_metadata_php';$hits[]='embedded_php';$codeData.="\n".$parts['metadata'];}
   }elseif($completeFile){
    // A complete JPEG without an EOI is structurally invalid; truncated read is not.
    $hits[]='image_structure_invalid';
   }
  }elseif(self::media($ext) && $type==='png'){
   $end=self::png_end($bytes);
   $tail=$end===false?'':substr($bytes,$end);
   if(self::php_payload($tail)){$hits[]='embedded_php';$codeData=$tail;}
   elseif(self::php_payload($bytes)){$hits[]='embedded_php';$codeData=$bytes;}
  }elseif(self::media($ext)){
   if(self::php_payload($data)){$hits[]='embedded_php';$codeData=$data;}
  }else{$codeData=$data;}
  // Raw image entropy must never satisfy command-execution heuristics.
  if($codeData!==''){
   if(preg_match('/\b(?:shell_exec|system|passthru|proc_open|popen|exec)\s*\(/i',$codeData))$hits[]='shell_function';
   if(preg_match('/\b(?:bzdecompress|gzdecode|gzuncompress|gzinflate)\s*\(/i',$codeData))$hits[]='decompression_loader';
   if(preg_match('/\b(?:eval|assert)\s*\(/i',$codeData) && preg_match('/\$_(?:POST|GET|REQUEST|COOKIE)\b/i',$codeData))$hits[]='request_code_execution';
   if(preg_match('/\b(?:shell_exec|system|passthru|proc_open|popen|exec)\s*\(/i',$codeData) && preg_match('/\$_(?:POST|GET|REQUEST|COOKIE)\b/i',$codeData))$hits[]='request_shell_execution';
   if(preg_match('/\bgoto\s+[a-zA-Z_][a-zA-Z_0-9]*\s*;/i',$codeData) && preg_match('/\beval\s*\(/i',$codeData))$hits[]='goto_exec_obfuscation';
  }
  return ['signals'=>array_values(array_unique($hits)),'detected_type'=>$type,'inspection'=>$inspection,'decoded_snippet'=>is_string($decoded)&&$decoded!==''?substr($decoded,0,131072):''];
 }
}
