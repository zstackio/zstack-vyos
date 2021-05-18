package main

import (
    "fmt"
    "syscall"
    "unsafe"
    "flag"
    "os"
    "errors"
)

func getPidLimits(pid int,oldlimit *(syscall.Rlimit)) error{
    _, _, e1 := syscall.RawSyscall6(syscall.SYS_PRLIMIT64, uintptr(pid), uintptr(syscall.RLIMIT_NOFILE), uintptr(unsafe.Pointer(nil)), uintptr(unsafe.Pointer(oldlimit)), 0, 0)
    if e1 != 0 {
        return e1
    }
    return nil
}

func setPidLimits(pid int,newlimit *syscall.Rlimit) error{
    _, _, e1 := syscall.RawSyscall6(syscall.SYS_PRLIMIT64, uintptr(pid), uintptr(syscall.RLIMIT_NOFILE), uintptr(unsafe.Pointer(newlimit)), uintptr(unsafe.Pointer(nil)), 0, 0)
    if e1 != 0 {
        return e1
    }
    return nil
}

func setLimits(pid int,newLimit *syscall.Rlimit) error {
    var oldLimit syscall.Rlimit

    err := getPidLimits(pid,&oldLimit)
    if err != nil {
        return err
    }

    if (newLimit.Cur<=0 ) {
        fmt.Printf("error: rlimit can not 0\n",)
        return errors.New("error number")
    }

    if (newLimit.Cur > oldLimit.Max) {
        fmt.Printf("warn: rlimit soft %v must not exceed rlimit hard %v \n", newLimit.Cur,oldLimit.Max)
        newLimit.Cur = oldLimit.Max
    }

    newLimit.Max = oldLimit.Max
    err = setPidLimits(pid, newLimit)
    if err != nil {
        fmt.Printf("error: can not set pid %v rlimit soft:%v,error: %s \n", pid,newLimit.Cur, err)
        return err
    }

    err = getPidLimits(pid,&oldLimit)
    if err != nil {
        return err
    }
    fmt.Printf("set pid %v rlimit soft:%v hard:%v \n",pid,oldLimit.Cur,oldLimit.Max)
    return nil
}

func main(){
    var rLimit,newLimit syscall.Rlimit
    var pid int
    var softLimit uint64
    mypid := os.Getpid()
    err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
    if err != nil {
        fmt.Printf("can not get pid %v rlimit\n",mypid)
        os.Exit(1)
    }
    flag.IntVar(&pid, "p", mypid, "progress id")
    flag.Uint64Var(&softLimit, "s", rLimit.Cur, "fd soft limit")
    flag.Parse()
    newLimit.Cur = softLimit
    setLimits(pid,&newLimit)   
}