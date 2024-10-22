Run `localsecret` [check here for new releases](https://github.com/scrtlabs/LocalSecret/pkgs/container/localsecret)

```sh
docker run -it \
	-p 1317:1317 -p 5000:5000 -p 9090:9090 -p 9091:9091 -p 26657:26657\
	--name localsecret ghcr.io/scrtlabs/localsecret:v1.14.2
```
