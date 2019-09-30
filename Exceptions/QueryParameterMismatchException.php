<?php

namespace Circle\DoctrineRestDriver\Exceptions;

class QueryParameterMismatchException extends DoctrineRestDriverException
{
    /**
     * @param $query
     * @param $needle
     */
    public function __construct($query, $needle)
    {
        parent::__construct("Either the provided query is invalid or there are more parameters than {$needle}-placeholders in:\n{$query}");
    }
}
