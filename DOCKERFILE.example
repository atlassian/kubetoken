FROM ubuntu:16.04
RUN apt-get update && apt-get install ca-certificates -y
ADD kubetokend /bin/kubetokend
ENV PORT 8080
EXPOSE 8080
ENTRYPOINT ["/bin/kubetokend", "--ldap", "ldap.example.com"]

