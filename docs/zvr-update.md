# zvr.bin 更新流程优化


### 1. 新增改动
> 在`zstack-vyos`中新增data/ 目录，仅仅修改了`makefile`和`install-zvr.sh`，对原代码影响较小。

```
root@debian:~/zstack-vyos# tree data
data
├── config
│   ├── deb_config         //控制deb包的安装/卸载
│   └── file_config        //控制文件的删除/替换
├── file-lists   //需要替换或添加的文件列表
│   ├── modules
│   └── zstack_repos.list
├── hooks    //更新zvr.bin时执行的脚本
│   ├── 00_exec_hooks.sh
│   ├── 01_sync_conf_file.sh
│   ├── 02_install_package.sh
│   ├── 03_load_driver.sh
│   ├── ......
│   └── hook_function
└── repos   //预安装deb包
    ├── hping3_3.a2.ds2-6_amd64.deb
    ├── i40e_2.17.15-1_amd64.deb
    ├── ......
    ├── strace_4.5.20-2_amd64.deb
    └── strongswan-zstack_5.9.4-1_amd64.deb

```

### 2. 实际操作
#### 2.1 如何替换/删除系统文件？
> 比如需要替换系统中`/etc/modules`文件，只需要将`modules`文件放入`file-lists`目录下，然后修改`file_config`

```
root@debian:~/zstack-vyos# cat data/config/file_config 
[uninstall]
# Use for delete files
#

[install]
# Use for add/sync files
# default path is data/conf/
modules             /etc/                      0664    root:root
```
- **[uninstall]**：表示需要删除的系统文件

- **[install]**：表示需要替换或添加的文件，格式固定为：`newFile`  `fileDir`  `fileMode` `fileOwner`

    **注意** : 脚本会自动在`data/file-lists/`目录下查找`newFile`

#### 2.2 如何安装/卸载deb包？
> 比如想要安装`strace` 的`deb`包，只需要将`strace_4.5.20-2_amd64.deb` 放到`repos`目录下，然后在`config/deb_config`文件中添加`strace`即可：

```
root@debian:~/zstack-vyos# cat data/config/deb_config 
[uninstall]
# use for remove deb

[install]
# use for install deb
iperf
strace
strongswan-zstack
```
- **[uninstall]**：表示需要删除的系统文件

- **[install]**：表示需要替换或添加文件，格式为：`newFile`  `fileDir`  `fileMode` `fileOwner`

#### 2.3 如何添加脚本？
> `zvr.bin`安装时可能不止需要拷贝文件，我们还希望能执行一些简单的脚本。这些脚本可直接放在data/hooks/目录下，更新zvr时会自动调用。

**注意：不能执行阻塞或者等待时间较长的脚本**