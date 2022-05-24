## zvr.bin 更新流程优化


### 1. 新增改动
> 在`zstack-vyos`中新增data/ 目录，仅仅修改了`makefile`和`install-zvr.sh`，对原代码影响较小。

```
root@debian:~/zstack-vyos# tree data/
data
├── config
│   ├── includes-arm.list   //aarch64架构下，控制文件的删除/替换
│   ├── includes-x86.list   //x86_64架构下，控制文件的删除/替换
│   ├── packages-arm.list   //aarch64架构下，控制deb包的删除/安装
│   └── packages-x86.list   //x86_64架构下，控制deb包的删除/安装
├── hooks  //更新zvr.bin时执行的脚本
│   ├── 00_exec_hooks.sh
│   ├── 01_sync_conf_file.sh
│   ├── 02_install_package.sh
│   ├── 03_load_driver.sh
│   └── hook_function
├── includes-lists
│    └── x86  //x86_64架构下需要替换或添加的文件列表
│       └── modules
└── repos
    └── x86  //x86_64架构下预安装deb包
        ├── iperf_2.0.4-5_amd64.deb
        ├── strace_4.5.20-2_amd64.deb
        └── strongswan-zstack_5.9.4-1_amd64.deb
```

### 2. 实际操作
#### 2.1 如何替换/删除系统文件？
> 比如需要在x86_64架构的系统中替换`/etc/modules`文件，只需要将`modules`文件放入`includes-lists/x86/`目录下，然后在`includes-x86.list`文件添加条目。

```
root@debian:~/zstack-vyos# cat data/config/includes-x86.list
[uninstall]
# Use for delete files
#

[install]
# Use for add/sync files
# default path is data/conf/
modules             /etc/                      0664    root:root
```
- **[uninstall]**：表示需要删除的系统文件

- **[install]**：表示需要替换或添加的文件，格式固定为：`SrcFile`  `fileDir`  `fileMode` `fileOwner`

    **注意** : 脚本会自动在`data/includes-lists/`目录下查找`SrcFile`

#### 2.2 如何安装/卸载deb包？
> 比如需要在x86_64架构的系统中安装`strace` 的`deb`包，只需要将`strace_4.5.20-2_amd64.deb` 放到`repos/x86/`目录下，然后在`config/packages-x86.list`文件中添加`strace`即可：

```
root@debian:~/zstack-vyos# cat data/config/packages-x86.list 
[uninstall]
# use for remove deb packages

[install]
# use for install deb packages
iperf
strace
strongswan-zstack
```
- **[uninstall]**：表示需要删除的deb包

- **[install]**：表示需要安装的deb包

#### 2.3 如何添加脚本？
> `zvr.bin`安装时可能不止需要拷贝文件，我们还希望能执行一些简单的脚本。这些脚本可直接放在data/hooks/目录下，更新zvr时会自动调用。

**注意：不能执行阻塞或者等待时间较长的脚本**