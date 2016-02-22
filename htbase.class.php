<?php

abstract class htbase {


	private $htFile= "";
	
	function htbase ($htFile = "")
	{
		if(!empty($htFile))
		{
			$this->init($htFile);
		}
		return;
	}

	function init ($htFile)
	{
		$this->htFile	= $htFile;

		if(empty($htFile))
		{		
			$this->error("Empty file passed to init",1);
		}
		
		if ($this->canRead()) {
			$this->loadFile();
		}
	}

	function reload() {
		$this->loadFile();
	}		
	
	function canRead ($filename = "")
	{		
	
		if (empty($filename)) {
			$filename = $this->htFile;
		}
		
		if (!(file_exists($filename))) {
			//empty file is OK.		
			return true;
		}
		
		if (!(is_readable($filename)))
		{
			$this->error("File [$filename] not readable",0);
			return false;
		}
		
		if(is_dir($filename))
		{
			$this->error("File [$filename] is a directory",0);
			return false;
		}		

		return true;
	}
	
    function canModify() {    	
    	
    	if (!file_exists($this->htFile)) {
    		return is_writable(dirname($this->htFile));	
    	}
    	
    	if(is_link($this->htFile))
		{
			$this->error("File [$this->htFile] is a symlink",0);
			return false;
		}
    
    	return is_writable($this->htFile);
    }
    
    protected function htFile() {
    	return $this->htFile;
    }
    
    protected abstract function loadFile();
    protected abstract function writeFile();
    
	protected function error($text,$level=0) {
		msg($text,$level);	
	}
	
	
}
?>