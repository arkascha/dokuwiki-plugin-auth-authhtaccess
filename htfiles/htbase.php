<?php

/**
 * Class auth_plugin_authhtaccess_htbase
 */
abstract class auth_plugin_authhtaccess_htbase
{
    /** @var string file name */
    private $htFile = '';

    /**
     * auth_plugin_authhtaccess_htbase constructor.
     * @param string $htFile
     */
    public function __construct($htFile = '') {
        if(!empty($htFile)) {
            $this->init($htFile);
        }
        return;
    }

    /**
     * @param $htFile string file path
     */
    public function init($htFile) {
        $this->htFile = $htFile;

        if(empty($htFile)) {
            $this->error("Empty file passed to init", 1);
        }

        if ($this->canRead()) {
            $this->loadFile();
        }
    }

    /**
     * @brief Reload file from disk.
     */
    public function reload() {
        $this->loadFile();
    }

    /**
     * @param string $fileName
     * @return bool
     */
    public function canRead($fileName = '') {
        if (empty($fileName)) {
            $fileName = $this->htFile;
        }

        if (!(file_exists($fileName))) {
            //empty file is OK.
            return true;
        }

        if (!(is_readable($fileName))) {
            $this->error("File [$fileName] not readable", 0);
            return false;
        }

        if(is_dir($fileName)) {
            $this->error("File [$fileName] is a directory", 0);
            return false;
        }

        return true;
    }

    /**
     * @return bool
     */
    public function canModify() {
        if (!file_exists($this->htFile)) {
            return is_writable(dirname($this->htFile));
        }

        if(is_link($this->htFile)) {
            $this->error("File [$this->htFile] is a symlink", 0);
            return false;
        }

        return is_writable($this->htFile);
    }

    /**
     * @return string
     */
    protected function htFile() {
        return $this->htFile;
    }

    /**
     * @brief Load file from disk.
     */
    protected abstract function loadFile();

    /**
     * @brief Write file to disk.
     */
    protected abstract function writeFile();

    /**
     * @param $text
     * @param int $level
     */
    protected function error($text, $level = 0) {
        msg($text, $level);
    }
}
