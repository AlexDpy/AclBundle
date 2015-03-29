<?php

namespace AlexDpy\AclBundle\DataCollector\Collector;


use AlexDpy\AclBundle\Manager\AclCheckerInterface;
use AlexDpy\AclBundle\Manager\AclIdentifierInterface;
use Symfony\Component\Security\Acl\Voter\FieldVote;

class AclCheckerCollector implements AclCheckerInterface
{
    /**
     * @var AclCheckerInterface
     */
    private $aclChecker;

    /**
     * @var array
     */
    private $checks;

    /**
     * @var \ReflectionMethod
     */
    private $getObjectToSecure;

    /**
     * @var AclIdentifierInterface
     */
    private $aclIdentifier;

    /**
     * @param AclCheckerInterface $aclChecker
     */
    public function __construct(AclCheckerInterface $aclChecker)
    {
        $this->getObjectToSecure = new \ReflectionMethod('AlexDpy\AclBundle\Manager\AclChecker', 'getObjectToSecure');
        $this->getObjectToSecure->setAccessible(true);

        $aclIdentifierProperty = new \ReflectionProperty('AlexDpy\AclBundle\Manager\AclChecker', 'aclIdentifier');
        $aclIdentifierProperty->setAccessible(true);
        $this->aclIdentifier = $aclIdentifierProperty->getValue($aclChecker);

        $this->aclChecker = $aclChecker;
        $this->checks = [];
    }

    /**
     * @param bool  $result
     * @param float $startTime
     */
    private function collectCheck($result, $startTime)
    {
        $time = (microtime(true) - $startTime) * 1000;

        $backtrace = debug_backtrace(0, 2)[1];

        $oidType = 'Class' === substr($backtrace['function'], -5)
            ? AclIdentifierInterface::OID_TYPE_CLASS
            : AclIdentifierInterface::OID_TYPE_OBJECT;

        if ('is' === substr($backtrace['function'], 0, 2)) {
            $attributes = $backtrace['args'][0];
            $field = isset($backtrace['args'][2]) ? $backtrace['args'][2] : null;
            $oid = $this->getObjectToSecure->invoke($this->aclChecker, $oidType, $backtrace['args'][1], $field);
            $sid = $this->aclIdentifier->getUserSecurityIdentity();
        } else {
            $sid = 'role' === substr($backtrace['function'], 0, 4)
                ? $this->aclIdentifier->getRoleSecurityIdentity($backtrace['args'][0])
                : $this->aclIdentifier->getUserSecurityIdentity($backtrace['args'][0]);
            $attributes = $backtrace['args'][1];
            $field = isset($backtrace['args'][3]) ? $backtrace['args'][3] : null;
            $oid = $this->getObjectToSecure->invoke($this->aclChecker, $oidType, $backtrace['args'][2], $field);
        }

        $isFieldVote = $oid instanceof FieldVote;

        $this->checks[] = [
            'method' => $backtrace['function'],
            'result' => $result,
            'attributes' => (array) $attributes,
            'oid' => $isFieldVote ? $oid->getDomainObject() : $oid,
            'sid' => $sid,
            'field' => $isFieldVote ? $oid->getField() : null,
            'time' => $time
        ];
    }

    /**
     * @return array
     */
    private function getChecks()
    {
        return $this->checks;
    }

    /**
     * {@inheritdoc}
     */
    public function isGrantedOnClass($attributes, $class, $field = null)
    {
        $startTime = microtime(true);
        $isGranted = $this->aclChecker->isGrantedOnClass($attributes, $class, $field);
        $this->collectCheck($isGranted, $startTime);

        return $isGranted;
    }

    /**
     * {@inheritdoc}
     */
    public function isGrantedOnObject($attributes, $object, $field = null)
    {
        $startTime = microtime(true);
        $isGranted = $this->aclChecker->isGrantedOnObject($attributes, $object, $field);
        $this->collectCheck($isGranted, $startTime);

        return $isGranted;
    }

    /**
     * {@inheritdoc}
     */
    public function roleIsGrantedOnClass($role, $attributes, $class, $field = null)
    {
        $startTime = microtime(true);
        $isGranted = $this->aclChecker->roleIsGrantedOnClass($role, $attributes, $class, $field);
        $this->collectCheck($isGranted, $startTime);

        return $isGranted;
    }

    /**
     * {@inheritdoc}
     */
    public function roleIsGrantedOnObject($role, $attributes, $object, $field = null)
    {
        $startTime = microtime(true);
        $isGranted = $this->aclChecker->roleIsGrantedOnObject($role, $attributes, $object, $field);
        $this->collectCheck($isGranted, $startTime);

        return $isGranted;
    }

    /**
     * {@inheritdoc}
     */
    public function userIsGrantedOnClass($user, $attributes, $class, $field = null)
    {
        $startTime = microtime(true);
        $isGranted = $this->aclChecker->userIsGrantedOnClass($user, $attributes, $class, $field);
        $this->collectCheck($isGranted, $startTime);

        return $isGranted;
    }

    /**
     * {@inheritdoc}
     */
    public function userIsGrantedOnObject($user, $attributes, $object, $field = null)
    {
        $startTime = microtime(true);
        $isGranted = $this->aclChecker->userIsGrantedOnObject($user, $attributes, $object, $field);
        $this->collectCheck($isGranted, $startTime);

        return $isGranted;
    }

    /**
     * @param $method
     * @param $arguments
     * @return mixed
     */
    public function __call($method, $arguments)
    {
        return call_user_func_array([$this->aclChecker, $method], $arguments);
    }
}
