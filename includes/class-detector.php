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
 /** Locate the JPEG EOI outside length-delimited metadata and entropy-escaped bytes. */
 static function jpeg_end($bytes){
  $length=strlen($bytes); if($length<4 || substr($bytes,0,3)!=="\xff\xd8\xff")return false;
  $i=2;$entropy=false;
  while($i<$length-1){
   if(ord($bytes[$i])!==255){if($entropy){$i++;continue;}return false;}
   $markerAt=$i;
   while($i<$length && ord($bytes[$i])===255)$i++;
   if($i >= $length)return false;
   $marker=ord($bytes[$i++]);
   if($marker===0){if(!$entropy)return false;continue;}
   if($marker===0xd9)return $i;
   if($marker===0xd8 || $marker===0x01 || ($marker>=0xd0 && $marker<=0xd7))continue;
   if($i+2>$length)return false;
   $size=(ord($bytes[$i])<<8)|ord($bytes[$i+1]);
   if($size<2 || $i+$size>$length)return false;
   $i+=$size;
   if($marker===0xda)$entropy=true;
  }
  return false;
 }
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
  return (bool)(($hasExec && ($hasRequest || $hasStatement)) || ($hasRequest && $hasStatement));
 }
 static function inspect($bytes,$ext){
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
   $end=self::jpeg_end($bytes);
   if($end!==false){
    // JPEG compressed entropy can contain arbitrary byte patterns. Only evaluate
    // trailing bytes as source; detect suspicious meaningful code in metadata
    // separately, never flag a lone <?= inside legitimate pixel data.
    $tail=substr($bytes,$end);
    if(self::php_payload($tail)){$hits[]='embedded_php';$codeData=$tail;}
    elseif(self::php_payload($bytes)){
     // A credible full PHP payload may occur inside metadata/APP segments.
     // This is not triggered by opening markers alone.
     $hits[]='embedded_php';$codeData=$bytes;
    }
   }elseif(self::php_payload($bytes)){$hits[]='embedded_php';$codeData=$bytes;}
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
