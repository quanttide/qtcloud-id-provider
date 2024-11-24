# 量潮Python项目示例

## 环境配置

1. 安装 Python 环境：

   前往 [https://www.python.org/](https://www.python.org/) 下载安装 Python (>= 3.10)，然后在命令行中执行：

    ```shell
    pip install pdm
    pdm install
    ```

   若下载缓慢，可换源：

    ```shell
    pip config set global.index-url https://mirrors.aliyun.com/pypi/simple
    ```

2. 在`项目根目录`下执行以下命令安装依赖项：

   ```shell
   pdm install
   ```

## 运行

1. 在`项目根目录`下执行以下命令：

   ```shell
   pdm run python project_name/__main__.py
   ```
