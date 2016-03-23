<?php
namespace Puz\SimpleCrypt;

class Crypt
{
    /**
     * @var string;
     */
    protected $name;

    /**
     * @var string
     */
    protected $password;

    /**
     * @var string
     */
    protected $folder;

    /**
     * @var
     */
    protected $publicKey;

    /**
     * @var
     */
    protected $privateKey;

    /**
     * Crypt constructor.
     * @param null $password
     * @param null $folder
     * @param string $name
     */
    public function __construct($password = null, $folder = null, $name = "simplecrypt")
    {
        $this->setFolder($folder);
        $this->name = $name;
        $this->password = $password;

        // When everything is set, check if the files already exists. If not, the user will have to call a method to create them.
    }

    /**
     * @param string $folder
     * @throws \Exception If invalid folder destination
     * @return bool
     */
    public function setFolder($folder = null)
    {
        if (empty($folder)) {
            throw new \Exception("We strongly suggest that you put your encryption keys outside public webspace. So strongly that we won't allow that you don't give us a path");
        } elseif (!is_dir($folder)) {
            throw new \Exception("The given folder does not exists or have wrong permissions");
        } else {
            $this->folder = $folder;
            return true;
        }
    }

    /**
     * @param $string The string to encrypt
     * @return string
     */
    public function encrypt($string)
    {
        openssl_public_encrypt($string, $encrypted, $this->publicKey);
        return base64_encode($encrypted);
    }

    /**
     * @param $encrypted The encrypted string to decrypt
     * @return mixed
     * @throws \Exception
     */
    public function decrypt($encrypted)
    {
        if ($this->privateKey === false) {
            throw new \Exception("The password given in the constructor is the wrong key password. Could not decrypt.");
        }

        $valid = openssl_private_decrypt(base64_decode($encrypted), $decrypted, $this->privateKey);
        if(!$valid) return $valid;
        else return $decrypted;

    }

    /**
     * @return bool
     */
    public function isFilesCreated()
    {
        $folder = $this->folder;
        $public = $folder . DIRECTORY_SEPARATOR . (!empty($this->name) ? $this->name . "_" : "") . "public.pem";
        $private = $folder . DIRECTORY_SEPARATOR . (!empty($this->name) ? $this->name . "_" : "") . "private.pem";

        if (is_file($public) && is_file($private)) {
            $this->publicKey = openssl_get_publickey(file_get_contents($public));
            $this->privateKey = openssl_get_privatekey(file_get_contents($private), $this->password);

            return true;
        } else {
            return false;
        }
    }

    /**
     * @param bool $force
     * @throws \Exception
     */
    public function createKeys($force = false)
    {
        if (!$this->isFilesCreated() || $force) {
            $folder = $this->folder;
            $public = $folder . DIRECTORY_SEPARATOR . (!empty($this->name) ? $this->name . "_" : "") . "public.pem";
            $private = $folder . DIRECTORY_SEPARATOR . (!empty($this->name) ? $this->name . "_" : "") . "private.pem";

            $config = array(
                'digest_alg' => 'sha512',
                'private_key_bits' => 4096,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
                'encrypt_key' => true
            );

            // Create the private and public key
            $res = openssl_pkey_new($config);

            // Extract the private key from $res to $privateKey
            openssl_pkey_export($res, $privateKey, $this->password);

            // Extract the public key from $res to $pubKey
            $pubKey = openssl_pkey_get_details($res);
            $pubKey = $pubKey["key"];

            // Store the keys
            file_put_contents($private, $privateKey);
            file_put_contents($public, $pubKey);
        } else {
            throw new \Exception("Keys already created. You can loose data if you overrides your keys. Are you sure you want to do that? (Call the method again with \$force = true)");
        }
    }
}


/**
 * private function getKey(){
//Loading the Private key and authenticating,
if(file_exists($this->path."/private.key") && file_exists($this->path."/public.key")){
$this->private = @openssl_get_privatekey(file_get_contents($this->path."/private.key"), $this->password);
$this->public = @openssl_get_publickey(file_get_contents($this->path."/public.key"));
}
else{
throw new Exception("NØKLENE ER FORSVUNNET! DET MÅ GENERERE NYE, OG HÅPER FOR DIN SKYLD AT DU IKKE HAR NOE KRYPTERT ENDA!");
}
}
 */
