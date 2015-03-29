<?php

namespace AlexDpy\AclBundle\DataCollector\Collector;

use AlexDpy\AclBundle\Manager\AclFilterInterface;
use Doctrine\DBAL\Query\QueryBuilder as DBALQueryBuilder;
use Doctrine\ORM\Query as ORMQuery;
use Symfony\Component\Security\Core\User\UserInterface;

class AclFilterCollector implements AclFilterInterface
{
    /**
     * @var AclFilterInterface
     */
    private $aclFilter;

    /**
     * @var array
     */
    private $filters;

    /**
     * @param AclFilterInterface $aclFilter
     */
    public function __construct(AclFilterInterface $aclFilter)
    {
        $this->aclFilter = $aclFilter;
        $this->filters = [];
    }

    /**
     * @param DBALQueryBuilder|ORMQuery $result
     * @param float                     $startTime
     */
    private function collectFilter($result, $startTime)
    {
        $time = (microtime(true) - $startTime) * 1000;

        $backtrace = debug_backtrace(0, 2)[1];

        $this->filters[] = [
            'method' => $backtrace['function'],
            'query' => $result->getSQL(),
            'time' => $time
        ];
    }

    /**
     * @return array
     */
    private function getFilters()
    {
        return $this->filters;
    }

    /**
     * {@inheritdoc}
     */
    public function apply(
        $queryBuilder,
        $permission,
        $oidClass,
        $oidReference,
        UserInterface $user = null,
        array $orX = []
    ) {
        $startTime = microtime(true);
        $result = $this->aclFilter->apply($queryBuilder, $permission, $oidClass, $oidReference, $user, $orX);
        $this->collectFilter($result, $startTime);

        return $result;
    }

    /**
     * @param $method
     * @param $arguments
     * @return mixed
     */
    public function __call($method, $arguments)
    {
        return call_user_func_array([$this->aclFilter, $method], $arguments);
    }
}
