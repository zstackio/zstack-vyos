## zvr.bin更新与制作镜像流程优化


### 1. 新增改动
> 在`zstack-vyos`中新增目录data/，用于处理zvr更新和vyos镜像的制作。

下面是data/目录的结构：
```
root@debian:~/zstack-vyos# tree data/
data
├── config
│   ├── bootup-config.install  //重连路由器时，配置预安装的文件
│   └── update-zvr.install     //制作镜像时，配置预安装的文件
├── file-lists      // 待安装的文件列表
│   ├── conntrackd.conf
│   ├── cpu-monitor
│   ├── ......
│   ├── zstack-virtualrouteragent
│   ├── zvr-monitor.sh
│   └── zvr-reboot.sh
├── hooks   //重连后的执行脚本（按照序列号自动执行）
│   ├── 00_exec_hooks.sh
│   ├── 01_sync_conf_file.sh
│   ├── 03_pre_install.sh
│   ├── 05_install_package.sh
│   ├── 08_post_install.sh
│   └── hook_function
├── repos     //重连路由器后，需要安装的deb包
│   ├── iperf_2.0.4-5_amd64.deb
│   └── strace_4.5.20-2_amd64.deb
└── upgrade     //用于软件的更新
    └── strongswan
        ├── 5.9.4
        │   ├── ipsec.conf
        │   ├── ipsec.secrets
        │   ├── strongswan.conf
        │   ├── strongswan-zstack_5.9.4-1_amd64.deb
        │   └── upgrade.sh
        └── origin
            └── upgrade.sh
```

### 2. 实际操作
#### 2.1 如何安装文件到vyos系统中？
> 比如需要在x86_64架构的系统中替换`/etc/modules`文件，只需要将`modules`文件放入`data/file-lists/`目录下，然后在`update-zvr.install`文件中的`[[X86]]`下添加条目。

> 比如需要在所有架构中替换`sysctl.conf`文件，将`sysctl.conf`文件放入`data/file-lists/`目录下，在`update-zvr.install`文件中的`[[GENERIC]]`下添加条目。

```
root@debian:~/zstack-vyos# cat data/config/update-zvr.install
[[GENERIC]]
#
sysctl.conf             /etc/sysctl.conf                           0644     root:root

[[X86]]
#
modules                /etc/modules                         0644     root:root

[[ARM]]
#
keepalived_aarch64        /usr/sbin/keepalived           0755      vyos:users

[[MIPS]]
#

```
- [[GENERIC]]：所有架构上都会安装

- [[X86]]：仅安装在x86架构上

- [[ARM]]：仅安装在aarch64架构上

- [[MIPS]]：仅安装在mips64架构上

- entry format：格式固定为：`filename`  `fileDst`  `fileMode` `fileOwner`

#### 2.2 如何在镜像中安装文件

> 同上，配置文件是`bootup-config.install`，按行上述的步骤配置后，构建镜像并在系统启动后，文件会自动安装到指定位置。

下面是`bootup-config.install`的格式：
```
root@debian:~/zstack-vyos# cat data/config/bootup-config.install
[[GENERIC]]
#

[[X86]]
#

[[ARM]]
#

[[MIPS]]
#
```

#### 2.3 如何添加脚本？
> `zvr.bin`安装时可能不止需要拷贝文件，我们还希望能执行一些简单的脚本。这些脚本可直接放在data/hooks/目录下，更新zvr时会自动调用。

**注意：不能执行阻塞或者等待时间较长的脚本**