# openGM-CA Docker构建文件
# 基于openEuler最小化镜像

FROM openeuler/openeuler:22.03-lts-sp3 AS builder

# 安装Go编译环境
RUN yum install -y golang git make && \
    yum clean all

WORKDIR /build

# 复制依赖文件(利用Docker缓存层)
COPY go.mod go.sum ./
RUN go mod download

# 复制源码
COPY . .

# 编译二进制文件
RUN make build

# ============================================
# 运行阶段 - 最小化镜像
# ============================================
FROM openeuler/openeuler:22.03-lts-sp3

LABEL maintainer="openGM-CA Team"
LABEL description="国密CA证书签发系统"

# 安装运行时依赖
RUN yum install -y ca-certificates tzdata && \
    yum clean all && \
    rm -rf /var/cache/yum

# 设置时区
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# 创建运行用户(非root)
RUN groupadd -r opengm-ca && \
    useradd -r -g opengm-ca -s /sbin/nologin -d /var/lib/opengm-ca opengm-ca

# 创建目录结构
RUN mkdir -p /etc/opengm-ca/certs \
             /etc/opengm-ca/keys \
             /var/lib/opengm-ca \
             /var/log/opengm-ca && \
    chown -R opengm-ca:opengm-ca /etc/opengm-ca \
                                 /var/lib/opengm-ca \
                                 /var/log/opengm-ca && \
    chmod 700 /etc/opengm-ca/keys && \
    chmod 755 /etc/opengm-ca/certs

# 从构建阶段复制二进制文件
COPY --from=builder /build/build/opengm-ca /usr/local/bin/
COPY --from=builder /build/build/opengm-ca-cli /usr/local/bin/
COPY --from=builder /build/build/opengm-ca-init /usr/local/bin/

# 复制配置文件
COPY --from=builder /build/configs/ /etc/opengm-ca/

# 设置权限
RUN chown opengm-ca:opengm-ca /usr/local/bin/opengm-ca* && \
    chmod 755 /usr/local/bin/opengm-ca*

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -fsk https://localhost:8443/health || exit 1

# 暴露端口
EXPOSE 8443

# 切换到非root用户
USER opengm-ca

# 工作目录
WORKDIR /var/lib/opengm-ca

# 数据卷
VOLUME ["/etc/opengm-ca/certs", "/var/lib/opengm-ca", "/var/log/opengm-ca"]

# 启动命令
ENTRYPOINT ["/usr/local/bin/opengm-ca"]
CMD ["-config", "/etc/opengm-ca/config.yaml"]
