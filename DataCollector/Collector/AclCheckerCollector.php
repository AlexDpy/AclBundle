<?php

namespace AlexDpy\AclBundle\DataCollector\Collector;


use AlexDpy\AclBundle\Manager\AclCheckerInterface;
use AlexDpy\AclBundle\Manager\AclIdentifierInterface;
use Symfony\Component\Security\Acl\Voter\FieldVote;
use Symfony\Component\Stopwatch\Stopwatch;

class AclCheckerCollector implements AclCheckerInterface
{
    /**
     * @var AclCheckerInterface
     */
    private $aclChecker;

    /**
     * @var Stopwatch
     */
    private $stopwatch;

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
     * @param Stopwatch           $stopwatch
     */
    public function __construct(AclCheckerInterface $aclChecker, Stopwatch $stopwatch)
    {
        $this->getObjectToSecure = new \ReflectionMethod('AlexDpy\AclBundle\Manager\AclChecker', 'getObjectToSecure');
        $this->getObjectToSecure->setAccessible(true);

        $aclIdentifierProperty = new \ReflectionProperty('AlexDpy\AclBundle\Manager\AclChecker', 'aclIdentifier');
        $aclIdentifierProperty->setAccessible(true);
        $this->aclIdentifier = $aclIdentifierProperty->getValue($aclChecker);

        $this->aclChecker = $aclChecker;
        $this->stopwatch = $stopwatch;
        $this->checks = [];
    }

    /**
     * @param string $function
     * @param array  $arguments
     *
     * @return mixed
     */
    private function collectCheck($function, array $arguments)
    {
        $this->stopwatch->start('acl.checks');

        $result = call_user_func_array([$this->aclChecker, $function], $arguments);

        $periods = $this->stopwatch->stop('acl.checks')->getPeriods();

        $backtrace = debug_backtrace(0, 2)[1];

        $oidType = 'Class' === substr($function, -5)
            ? AclIdentifierInterface::OID_TYPE_CLASS
            : AclIdentifierInterface::OID_TYPE_OBJECT;

        if ('is' === substr($function, 0, 2)) {
            $attributes = $backtrace['args'][0];
            $field = isset($backtrace['args'][2]) ? $backtrace['args'][2] : null;
            $oid = $this->getObjectToSecure->invoke($this->aclChecker, $oidType, $backtrace['args'][1], $field);
            $sid = $this->aclIdentifier->getUserSecurityIdentity();
        } else {
            $sid = 'role' === substr($function, 0, 4)
                ? $this->aclIdentifier->getRoleSecurityIdentity($backtrace['args'][0])
                : $this->aclIdentifier->getUserSecurityIdentity($backtrace['args'][0]);
            $attributes = $backtrace['args'][1];
            $field = isset($backtrace['args'][3]) ? $backtrace['args'][3] : null;
            $oid = $this->getObjectToSecure->invoke($this->aclChecker, $oidType, $backtrace['args'][2], $field);
        }

        $isFieldVote = $oid instanceof FieldVote;

        $this->checks[] = [
            'method' => $function,
            'result' => $result,
            'attributes' => (array) $attributes,
            'oid' => $isFieldVote ? $oid->getDomainObject() : $oid,
            'sid' => $sid,
            'field' => $isFieldVote ? $oid->getField() : null,
            'time' => end($periods)->getDuration()
        ];

        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function isGrantedOnClass($attributes, $class, $field = null)
    {
        return $this->collectCheck(__FUNCTION__, func_get_args());
    }

    /**
     * {@inheritdoc}
     */
    public function isGrantedOnObject($attributes, $object, $field = null)
    {
        return $this->collectCheck(__FUNCTION__, func_get_args());
    }

    /**
     * {@inheritdoc}
     */
    public function roleIsGrantedOnClass($role, $attributes, $class, $field = null)
    {
        return $this->collectCheck(__FUNCTION__, func_get_args());
    }

    /**
     * {@inheritdoc}
     */
    public function roleIsGrantedOnObject($role, $attributes, $object, $field = null)
    {
        return $this->collectCheck(__FUNCTION__, func_get_args());
    }

    /**
     * {@inheritdoc}
     */
    public function userIsGrantedOnClass($user, $attributes, $class, $field = null)
    {
        return $this->collectCheck(__FUNCTION__, func_get_args());
    }

    /**
     * {@inheritdoc}
     */
    public function userIsGrantedOnObject($user, $attributes, $object, $field = null)
    {
        return $this->collectCheck(__FUNCTION__, func_get_args());
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
