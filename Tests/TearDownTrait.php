<?php
namespace Circle\DoctrineRestDriver\Tests;

trait TearDownTrait
{
    protected function restoreExceptionHandler(): void
    {
        while (true) {
            $previousHandler = set_exception_handler(static fn() => null);

            restore_exception_handler();

            if ($previousHandler === null) {
                break;
            }

            restore_exception_handler();
        }
    }


    public function tearDown(): void
    {
        parent::tearDown();

        $this->restoreExceptionHandler();
    }
}
