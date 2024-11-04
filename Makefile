SHELL:=/bin/bash
ifndef LOGDIR
LOGDIR:=./logs
endif

all:
	@make -s setup
	@make -s build
	@make -s test
	@make -s docs
	@make -s install

setup:

build:
	composer install -o -vv -n --ansi 2>&1
test:
	./vendor/phpmd/phpmd/src/bin/phpmd . text phpmd.xml --exclude vendor,logs,Tests/app
	php -S 127.0.0.1:3000 -t Tests/app 2>1 & ./vendor/phpunit/phpunit/phpunit -c phpunit.xml --coverage-html $(LOGDIR)/coverage
	ps -eaf | awk '/ph[p] -S/{ print $$2 }' | xargs kill
	rm 1
unit:
	php -S 127.0.0.1:3000 -t Tests/app 2>1 & ./vendor/phpunit/phpunit/phpunit -c phpunit.xml --coverage-html $(LOGDIR)/coverage
	ps -eaf | awk '/ph[p] -S/{ print $$2 }' | xargs kill
	rm 1
test-terminal:
	php -S 127.0.0.1:3000 -t Tests/app 2>1 & ./vendor/phpunit/phpunit/phpunit -c phpunit.xml --testdox
	ps -eaf | awk '/ph[p] -S/{ print $$2 }' | xargs kill
	rm 1
clean:
	ps -eaf | awk '/ph[p] -S/{ print $$2 }' | xargs kill
	rm 1
docs:

install:
