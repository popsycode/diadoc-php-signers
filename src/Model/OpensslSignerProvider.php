<?php
/**
 * User: ikovalenko
 */

namespace AgentSIB\Diadoc\Model;


use AgentSIB\Diadoc\Exception\SignerProviderException;
use Symfony\Component\Process\Exception\RuntimeException;
use Symfony\Component\Process\ProcessBuilder;

class OpensslSignerProvider implements SignerProviderInterface
{
    private $caFile;
    private $certFile;
    private $privateKey;
    private $opensslBin;

    public function __construct($caFile, $certFile, $privateKey, $opensslBin = '/usr/bin/openssl')
    {
        $this->caFile = $caFile;
        $this->certFile = $certFile;
        $this->privateKey = $privateKey;
        $this->opensslBin = $opensslBin;
    }

    private function getOpensslProcess(array $args = [], $input = null)
    {
        return ProcessBuilder::create($args)
            ->setPrefix($this->opensslBin)
            ->setInput($input)->getProcess();
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt($plainData)
    {
        $process = $this->getOpensslProcess([
            'smime',
            '-encrypt',
            '-binary',
            '-noattr',
            '-outform', 'DER',
            '-gost89',
            $this->certFile
        ], $plainData);

        try {
            return $process->mustRun()->getOutput();
        } catch (RuntimeException $e) {
            throw new SignerProviderException($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt($encriptedData)
    {
        $process = $this->getOpensslProcess([
            'smime',
            '-decrypt',
            '-binary',
            '-noattr',
            '-inform', 'der',
            '-inkey', $this->privateKey
        ], $encriptedData);

        try {
            return $process->mustRun()->getOutput();
        } catch (RuntimeException $e) {
            throw new SignerProviderException($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function sign($data)
    {
        $process = $this->getOpensslProcess([
            'smime',
            '-sign',
            '-binary',
            '-noattr',
            '-gost89',
            '-signer', $this->certFile,
            '-inkey', $this->privateKey,
            '-outform', 'der'
        ], $data);

        try {
            return $process->mustRun()->getOutput();
        } catch (RuntimeException $e) {
            throw new SignerProviderException($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function checkSign($data, $sign)
    {
        $file = tmpfile();
        $metaDatas = stream_get_meta_data($file);
        $tmpFilename = $metaDatas['uri'];
        fwrite($file, $data);

        $process = $this->getOpensslProcess([
            'smime',
            '-verify',
            '-binary',
            '-noattr',
            '-gost89',
            '-inform', 'der',
            '-CAfile', $this->caFile,
            '-content', $tmpFilename
        ], $sign);

        try {
            $result = $process->run();
            fclose($file);

            return $result == 0;
        } catch (RuntimeException $e) {
            throw new SignerProviderException($e->getMessage(), $e->getCode(), $e);
        }
    }
}