<?php
/**
 * File name: parse.php
 * Description: Projekt 1 do předmětu IPP 2020, FIT VUT
 * Athor: Mirka Kolaříková (xkolar76)
 * Date: 17.2.2020
 */
/*-------------------------------------MAIN--------------------------------------*/
$path = getcwd();
$recursive = 0;
$parse_script = "/parse.php";
$int_script = "/interpret.py";
$parse_only = 0;
$int_only = 0;
$jexamxml = "/pub/courses/ipp/jexamxml/jexamxml.jar";
argument_check($argc, $argv);

/*-------------------------------------------------------------------------------*/
function argument_check($argc, $argv){
	global $path;
	global $recursive;
	global $parse_script;
	global $int_script;
	global $parse_only;
	global $int_only;
	global $jexamxml;

	$options = getopt('',["help", "directory:", "recursive", "parse-script:","int-script:" ,"parse-only", "int-only","jexamxml:"]);

	if(array_key_exists('help', $options) && $argc != 2){
		fwrite(STDERR, "Bad arguments!\n");
		exit(10);}
	if($argc == 2 && $argv[1] == "--help"){ //--help -> valid argument
			echo 
			"------------------------------------NAPOVEDA----------------------------------\n".
			"Test.php pro automaticke testovani postupne aplikace parse.php a interpret.py\n".
			"--help\n".
			"--directory=path\n".
			"--recursive\n".
			"--parse-script=file\n".
			"--int-script=file\n".
			"--parse-only\n".
			"--int-only\n".
			"--jexamxml=file\n".
			"-----------------------------------------------------------------------------\n";
			exit(0);
	}

	if(array_key_exists('directory', $options)){
		$path = $options['directory'];
	}
	if(array_key_exists('recursive', $options)){
		$recursive = 1;
	}
	if(array_key_exists('parse-script', $options)){
		$parse_script = $options['parse-script'];
	}
	if(array_key_exists('int-script', $options)){
		$int_script = $options['int-script'];
	}
	if(array_key_exists('parse-only', $options)){
		if(array_key_exists('int-only', $options) || array_key_exists('int-script', $options)){
			fwrite(STDERR, "Bad arguments!\n");
			exit(10);
		}
		$parse_only = 1;
	}
	if(array_key_exists('int-only', $options)){
		if(array_key_exists('parse-only', $options) || array_key_exists('parse-script', $options)){
			fwrite(STDERR, "Bad arguments!\n");
			exit(10);
		}
		$int_only = 1;
	}
	if(array_key_exists('jexamxml', $options)){
		$jexamxml = $options['jexamxml'];
	}

}
?>