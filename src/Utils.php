<?php
namespace tuanlq11\encryption;

/**
 * Created by Mr.Tuan
 * User: lqt
 * Date: 1/7/16
 * Time: 2:33 PM
 */
class Utils
{
    /** @var  Utils */
    protected static $instance;
    /** @var  String */
    protected $privKey;
    /** @var  String */
    protected $pubKey;

    /**
     * Utils constructor.
     * @param String $privKey
     * @param String $pubKey
     */
    public function __construct($privKey = null, $pubKey = null)
    {
        $this->privKey = $privKey;
        $this->pubKey = $pubKey;
    }

    /**
     * @return mixed
     */
    public function getPrivKey()
    {
        return $this->privKey;
    }

    /**
     * @return mixed
     */
    public function getPubKey()
    {
        return $this->pubKey;
    }

    /**
     * @param String $privKey
     */
    public function setPrivKey($privKey)
    {
        $this->privKey = $privKey;
    }

    /**
     * @param String $pubKey
     */
    public function setPubKey($pubKey)
    {
        $this->pubKey = $pubKey;
    }

    /**
     * Get Instance of Util
     *
     * @param null $privKey
     * @param null $pubKey
     * @return Utils
     */
    public static function getInstance($privKey = null, $pubKey = null)
    {
        if (is_null(self::instance)) {
            self::$instance = new Utils($privKey, $pubKey);
        }

        return self::$instance;
    }


    /**
     * Generate new private and public key
     *
     * @param string $digest_alg
     * @param int $private_key_bits
     * @param int $private_key_type
     * @return void
     */
    public function generatePKey($digest_alg = "sha512", $private_key_bits = 4096, $private_key_type = OPENSSL_KEYTYPE_RSA)
    {
        $res = openssl_pkey_new([
            "digest_alg"       => $digest_alg,
            "private_key_bits" => $private_key_bits,
            "private_key_type" => $private_key_type,
        ]);

        openssl_pkey_export($res, $this->privKey);
        $pubKey = openssl_pkey_get_details($res);
        $this->pubKey = $pubKey["key"];
    }

    /**
     * Encrypted data
     *
     * @param $data
     * @return String
     */
    public function encrypt($data)
    {
        if (empty($this->pubKey))
            return false;
        openssl_public_encrypt($data, $encrypted, $this->pubKey);

        return $encrypted;
    }

    /**
     * Decrypt data encrypted
     *
     * @param $data
     * @return bool
     */
    public function decrypt($data)
    {
        if (empty($this->privKey))
            return false;

        openssl_private_decrypt($data, $decrypted, $this->privKey);

        return $decrypted;
    }
}
