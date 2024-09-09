# go-cidrman
golang CIDR block management utilities.

Inspired by the Python netaddr library:
* https://github.com/drkjam/netaddr/

## Build

*Note:* This project uses [Go Modules](https://blog.golang.org/using-go-modules) making it safe to work with it outside of your existing [GOPATH](http://golang.org/doc/code.html#GOPATH). The instructions that follow assume a directory in your home directory outside of the standard GOPATH (i.e `$HOME/development/EvilSuperstars/`).

Clone repository to: `$HOME/development/EvilSuperstars/`

```sh
$ mkdir -p $HOME/development/EvilSuperstars/; cd $HOME/development/EvilSuperstars/
$ git clone git@github.com:EvilSuperstars/go-cidrman
$ cd $HOME/development/EvilSuperstars/terraform-provider-jmespath
$ make build
```

## Test

```sh
$ cd $HOME/development/EvilSuperstars/terraform-provider-jmespath
$ make test
```
