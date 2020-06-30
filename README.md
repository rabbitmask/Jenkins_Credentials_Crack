# Jenkins_Credentials_Crack
Jenkins凭据解密脚本，增加对publish_over_ssh插件支持

# 鸣谢
>https://github.com/tweksteen/jenkins-decrypt

>https://github.com/bstapes/jenkins-decrypt
```
感谢来自原作者的解密思路，本工具仅在原工具基础上魔改增加了对publish_over_ssh插件的支持
关于对credentials.xml文件的凭据解密，依然安利以上工具，/鞠躬。
```

# Usge
```
# 单凭据解密：
python3 jenkins_credential.py <master.key> <hudson.util.Secret> <secretPassphrase>

# jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin.xml文件批量解密：
python3 jenkins_credentials.py <master.key> <hudson.util.Secret> <jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin.xml>"

# 涉及文件路径如下：
$JENKINS_HOME/secrets/master.key
$JENKINS_HOME/secrets/hudson.util.Secret
$JENKINS_HOME/jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin.xml
```
