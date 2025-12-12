```text
securechat/                     # 项目根目录
├── app.py                      # Flask 应用主入口文件：初始化应用、注册蓝图、启动 SocketIO
├── config.py                   # 配置模块：定义 SECRET_KEY、数据库 URI、调试模式等
├── requirements.txt            # Python 依赖列表，用于 pip install -r 安装所需库
├── instance/                   # Flask 实例文件夹（安全存放运行时文件）
│   └── chat.db                 # SQLite 数据库文件（存储用户、房间等数据，.gitignore 中应忽略）
├── static/                     # 静态资源目录（由 Flask 自动提供服务）
│   ├── css/                    # 样式表文件夹
│   │   └── style.css           # 全局 CSS 样式（登录页、聊天界面等）
│   └── js/                     # 前端 JavaScript 脚本
│       └── chat.js             # 核心前端逻辑：连接 Socket.IO、处理消息收发、执行端到端加密/解密
├── templates/                  # Jinja2 模板目录（Flask 默认模板位置）
│   ├── base.html               # 基础 HTML 模板（包含 <head> 和通用布局，其他页面继承它）
│   ├── login.html              # 用户登录页面（含表单和错误提示）
│   ├── register.html           # 用户注册页面
│   ├── create_room.html        # 创建聊天室页面：可输入自定义口令或生成随机口令
│   └── chat_room.html          # 聊天主界面：显示消息历史、输入框、发送按钮，集成实时通信
├── models.py                   # 数据库模型定义：使用 SQLAlchemy 声明 User、Room 等表结构
├── auth.py                     # 认证相关路由与逻辑：处理 /login、/register，集成 Flask-Login
├── chat.py                     # 聊天功能核心模块：定义 /room/<code> 路由 + Socket.IO 事件（join, send_message 等）
└── utils/                      # 工具函数模块（保持主逻辑简洁）
    ├── crypto.py               # （可选）后端辅助加密工具（如生成随机口令、哈希等，不处理 E2EE 密钥）
    └── room_manager.py         # 房间状态管理器（可选）：跟踪活跃房间、用户数等（可用内存字典或 DB 实现）
```
