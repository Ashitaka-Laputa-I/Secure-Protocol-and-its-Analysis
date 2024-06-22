此为Ashitaka-Laputa-I的大作业

### 第三方库

```shell
pip install pycryptodome cryptography tk ttkbootstrap
```

### 关联

- **crypto_utils.py**、**dh_utils.py**、**rsa_utils.py** 提供了基本的加密、签名和密钥交换功能。
- **secure_protocol.py** 使用了上述工具类来实现安全协议的各个步骤。
- **protocol_analysis.py** 分析了安全协议的执行过程，并依赖于安全协议的定义和功能。
- **gui.py** 提供了用户界面来显示和管理安全协议分析的进度和结果。
- **main.py** 是整个程序的入口，负责启动用户界面应用。