# 12.SMTP 配置

{% hint style="success" %}
对应的[页面地址](https://github.com/dani-garcia/vaultwarden/wiki/SMTP-configuration)
{% endhint %}

您可以配置 vaultwarden 通过 SMTP 代理来发送电子邮件：

```python
docker run -d --name vaultwarden \
  -e SMTP_HOST=<smtp.domain.tld> \
  -e SMTP_FROM=<vaultwarden@domain.tld> \
  -e SMTP_PORT=587 \
  -e SMTP_SSL=true \
  -e SMTP_USERNAME=<username> \
  -e SMTP_PASSWORD=<password> \
  -v /vw-data/:/data/ \
  -p 80:80 \
  vaultwarden/server:latest
```

当 `SMTP_SSL` 设置为 `true` 时（这是默认值），将仅接受 TLSv1.1 和 TLSv1.2 协议，并且 `SMTP_PORT` 默认为`587`。如果设置为 `false`，`SMTP_PORT` 则默认设置为 `25` 并将尝试加密（2020 年 3 月 12 日之前的代码不会尝试加密）。这是非常不安全的，仅在您知道您在做什么时才使用此设置。要以显式模式运行 SMTP，请将 `SMTP_EXPLICIT_TLS` 设置为 `true`。想要不登录也可以发送电子邮件，简单地将 `SMTP_USERNAME` 和 `SMTP_PASSWORD` 设置为空即可。

请注意，如果启用了 SMTP 和邀请，邀请将通过电子邮件发送给新用户。您必须使用 Vaultwarden 实例的基础 URL 来设置 `DOMAIN` 配置项，以生成正确的邀请链接：

```python
docker run -d --name vaultwarden \
...
-e DOMAIN=https://vault.example.com \
...
```

用户邀请链接有效期为 5 天，过期后需要重新发送邀请。

## SMTP 服务器 <a id="smtp-servers"></a>

正确配置 SMTP 服务器/中继并不是一件小事。Vaultwarden 使用的邮件库也不是最容易排除故障的。所以，除非你对自己设置这个特别感兴趣，否则使用外部服务可能更容易。

这里有几个免费的服务，每天可以发送 100-200 封邮件（对于大多数用例来说已经足够了）：

* [SendGrid](https://sendgrid.com/)
* [MailJet](https://www.mailjet.com/)

