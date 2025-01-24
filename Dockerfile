FROM alpine:3.21.2 as builder
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories
RUN apk add --no-cache gcc g++ make cmake
ADD . /app
WORKDIR /app
RUN make 
RUN ls /app

FROM alpine:3.21.2
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories
ARG TARGETARCH
COPY --from=builder /app/build/hook_execve.so /var/lib/hook_execve.so
ENV LD_PRELOAD=/var/lib/hook_execve.so
CMD [ "/bin/sh" ]
