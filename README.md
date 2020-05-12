# Welcome to TcpAS

你好，github！辣鸡的我来了:baby_chick:

这是小明在github发布的第一个程序，虽然代码简陋，原理简单，但它于我而言是具有里程碑式的意义的。如果您和小明一样，刚刚开始自己写一些小工具，那么像本程序这样的端口扫描工具一定是最好的学习对象！

## 介绍

这是一个利用python写的端口扫描工具，主要是对自己学习过的理论知识进行的一次实践。因此：

本程序仅供学习使用！

本程序仅供学习使用！

本程序仅供学习使用！



它的原理就是使用ACK包进行扫描，先检查那些端口没有被过滤（也就是对方端口不会相应接收的包），然后再使用SYN半连接快速扫描开放的端口。

## 使用

程序的功能不多并且使用非常简单，因为仅仅只是为了学习端口扫描的实现，达到这个目的就行了

1.进行指定端口扫描

> python3 TcpAS.py [target_ip]  [target port]

2.进行默认端口扫描

> python3  TcpAS.py --default

3.进行全端口扫描（非常慢，有待优化，不建议使用）

> python3 TcpAS.py --all





***

这里是平平无奇的隔壁班小明，你最熟悉的陌生人。

![pingpingwuqi](https://github.com/Arm1ng/TcpAS/blob/master/image/pingpingwuqi.png?raw=true)

👏👏👏
[个人介绍](https://baike.baidu.com/item/%E5%B0%8F%E6%98%8E/33553?fr=aladdin)
😂😂😂
[博客地址](https://blog.csdn.net/qq_42288123)
