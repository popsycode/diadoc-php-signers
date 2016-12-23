<?php
/**
 * User: ikovalenko
 */

namespace AgentSIB\Diadoc\Model;


use AgentSIB\Diadoc\Exception\SignerProviderException;

interface SignerProviderInterface
{
    /**
     * Encrypt plain data
     *
     * @param string $plainData Input data
     *
     * @throws SignerProviderException
     *
     * @return string encrypted data in DER format
     */
    public function encrypt($plainData);

    /**
     * Decrypt encrypted data
     *
     * @param string $encryptedData encrypted data in DER format
     *
     * @throws SignerProviderException
     *
     * @return string encrypted value
     */
    public function decrypt($encryptedData);

    /**
     * Sign data
     *
     * @param string $data Input data
     *
     * @throws SignerProviderException
     *
     * @return string Signature
     */
    public function sign($data);

    /**
     * Check signature for input data
     *
     * @param string $data Input data
     * @param string $sign Signature in DER format
     *
     * @throws SignerProviderException
     *
     * @return boolean sign is valid
     */
    public function checkSign($data, $sign);
}